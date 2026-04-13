// Copyright (c) SAS Institute Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package hlkx

import (
	"archive/zip"
	"errors"
	"io"
	"os"
	"path"
	"strings"

	"github.com/beevik/etree"
	"github.com/google/uuid"

	"github.com/mind-security/relic/v8/lib/certloader"
	"github.com/mind-security/relic/v8/lib/magic"
	"github.com/mind-security/relic/v8/lib/pkcs7"
	"github.com/mind-security/relic/v8/lib/pkcs9"
	"github.com/mind-security/relic/v8/lib/xmldsig"
	"github.com/mind-security/relic/v8/signers"
	"github.com/mind-security/relic/v8/signers/zipbased"
)

var Signer = &signers.Signer{
	Name:      "hlkx",
	Magic:     magic.FileTypeHLKX,
	CertTypes: signers.CertTypeX509,
	TestPath:  testPath,
	Transform: zipbased.Transform,
	Sign:      sign,
	Verify:    verify,
}

func init() {
	signers.Register(Signer)
}

func testPath(fp string) bool {
	return strings.EqualFold(path.Ext(fp), ".hlkx")
}

func sign(r io.Reader, cert *certloader.Certificate, opts signers.SignOpts) ([]byte, error) {
	m, err := mangleZip(r, opts.Hash)
	if err != nil {
		return nil, err
	}
	// Signature filename uses a UUID (GUID), as required by HLKX
	sigName := path.Join(xmlSigPath, strings.ReplaceAll(uuid.New().String(), "-", "")+".psdsxs")
	// Root rels → points to origin (signed)
	if err := m.newRels("", originPath, sigOriginType); err != nil {
		return nil, err
	}
	// Compute RelationshipTransform digest over original (non-sig) rels before
	// origin and sig rels are added to the package.
	if err := m.computeRootRelsRef(); err != nil {
		return nil, err
	}
	// Origin rels → points to signature (NOT signed for HLKX)
	if err := m.newRelsNoDigest(originPath, sigName, sigType); err != nil {
		return nil, err
	}
	// Origin file (NOT signed for HLKX)
	if err := m.addOrigin(); err != nil {
		return nil, err
	}
	// Embed the leaf certificate (HLKX always embeds certs)
	if err := m.addCerts(cert, sigName); err != nil {
		return nil, err
	}
	// Create signature XML and add to zip
	sigfile, err := m.makeSignature(cert, opts)
	if err != nil {
		return nil, err
	}
	if err := m.m.NewFile(sigName, sigfile); err != nil {
		return nil, err
	}
	// Write content types
	if err := m.newCtypes(); err != nil {
		return nil, err
	}
	patch, err := m.m.MakePatch(true)
	if err != nil {
		return nil, err
	}
	return opts.SetBinPatch(patch)
}

func verify(f *os.File, opts signers.VerifyOpts) ([]*signers.Signature, error) {
	// read zip file
	size, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		return nil, err
	}
	inz, err := zip.NewReader(f, size)
	if err != nil {
		return nil, err
	}
	files := make(zipFiles, len(inz.File))
	for _, zf := range inz.File {
		files[zf.Name] = zf
	}
	// find and parse the signature XML
	sig, certs, err := readSignature(files)
	if err != nil {
		return nil, err
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromString(string(sig)); err != nil {
		return nil, err
	}
	root := doc.Root()
	// basic verification of XML
	xs, err := xmldsig.Verify(root, ".", certs)
	if err != nil {
		return nil, err
	}
	// verify digests of files
	if err := checkManifest(files, xs.Reference); err != nil {
		return nil, err
	}
	// verify PKCS#9 timestamp token
	cs, err := checkTimestamp(root, xs.EncryptedDigest)
	if err != nil {
		return nil, err
	}
	psig := pkcs7.Signature{Intermediates: xs.Certificates, Certificate: xs.Leaf()}
	if psig.Certificate == nil {
		return nil, errors.New("leaf x509 certificate not found")
	}
	return []*signers.Signature{&signers.Signature{
		Hash: xs.Hash,
		X509Signature: &pkcs9.TimestampedSignature{
			Signature:        psig,
			CounterSignature: cs,
		},
	}}, nil
}
