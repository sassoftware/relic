//
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
//

package vsix

import (
	"archive/zip"
	"errors"
	"io"
	"os"
	"path"

	"github.com/beevik/etree"

	"github.com/sassoftware/relic/v7/lib/certloader"
	"github.com/sassoftware/relic/v7/lib/magic"
	"github.com/sassoftware/relic/v7/lib/pkcs7"
	"github.com/sassoftware/relic/v7/lib/pkcs9"
	"github.com/sassoftware/relic/v7/lib/xmldsig"
	"github.com/sassoftware/relic/v7/signers"
	"github.com/sassoftware/relic/v7/signers/zipbased"
)

var Signer = &signers.Signer{
	Name:      "vsix",
	Magic:     magic.FileTypeVSIX,
	CertTypes: signers.CertTypeX509,
	Transform: zipbased.Transform,
	Sign:      sign,
	Verify:    verify,
}

type zipFiles map[string]*zip.File

func init() {
	signers.Register(Signer)
	Signer.Flags().Bool("detach-certs", false, "(VSIX) Package certificates separately in the archive")
}

func sign(r io.Reader, cert *certloader.Certificate, opts signers.SignOpts) ([]byte, error) {
	detachCerts := opts.Flags.GetBool("detach-certs")
	m, err := mangleZip(r, opts.Hash)
	if err != nil {
		return nil, err
	}
	// add rels and origin to zip
	sigName := path.Join(xmlSigPath, calcFileName(cert.Leaf)+".psdsxs")
	if err := m.newRels("", originPath, sigOriginType); err != nil {
		return nil, err
	}
	if err := m.newRels(originPath, sigName, sigType); err != nil {
		return nil, err
	}
	if err := m.addOrigin(); err != nil {
		return nil, err
	}
	// add certs (optional)
	if detachCerts {
		if err := m.addCerts(cert, sigName); err != nil {
			return nil, err
		}
	}
	// sign and add ctypes
	sigfile, err := m.makeSignature(cert, opts, detachCerts)
	if err != nil {
		return nil, err
	}
	if err := m.m.NewFile(sigName, sigfile); err != nil {
		return nil, err
	}
	if err := m.newCtypes(detachCerts); err != nil {
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
	for _, f := range inz.File {
		files[f.Name] = f
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
