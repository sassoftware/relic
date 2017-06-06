/*
 * Copyright (c) SAS Institute Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package jar

// Sign Java archives

import (
	"archive/zip"
	"io"
	"os"

	"github.com/sassoftware/relic/lib/certloader"
	"github.com/sassoftware/relic/lib/magic"
	"github.com/sassoftware/relic/lib/signjar"
	"github.com/sassoftware/relic/lib/x509tools"
	"github.com/sassoftware/relic/signers"
	"github.com/sassoftware/relic/signers/zipbased"
)

var JarSigner = &signers.Signer{
	Name:      "jar",
	Magic:     magic.FileTypeJAR,
	CertTypes: signers.CertTypeX509,
	Transform: zipbased.Transform,
	Sign:      sign,
	Verify:    verify,
}

func init() {
	JarSigner.Flags().Bool("sections-only", false, "(JAR) Don't compute hash of entire manifest")
	JarSigner.Flags().Bool("inline-signature", false, "(JAR) Include .SF inside the signature block")
	JarSigner.Flags().String("key-alias", "RELIC", "(JAR) Alias to use for the signed manifest")
	signers.Register(JarSigner)
}

// sign a manifest and return the PKCS#7 blob
func sign(r io.Reader, cert *certloader.Certificate, opts signers.SignOpts) ([]byte, error) {
	argSectionsOnly, _ := opts.Flags.GetBool("sections-only")
	argInlineSignature, _ := opts.Flags.GetBool("inline-signature")
	argAlias, _ := opts.Flags.GetString("key-alias")
	if argAlias == "" {
		argAlias = "RELIC"
	}
	digest, err := signjar.DigestJarStream(r, opts.Hash)
	if err != nil {
		return nil, err
	}
	patch, ts, err := digest.Sign(cert, argAlias, argSectionsOnly, argInlineSignature)
	if err != nil {
		return nil, err
	}
	opts.Audit.SetCounterSignature(ts.CounterSignature)
	return opts.SetBinPatch(patch)
}

func verify(f *os.File, opts signers.VerifyOpts) ([]*signers.Signature, error) {
	inz, err := openZip(f)
	if err != nil {
		return nil, err
	}
	sigs, err := signjar.Verify(inz, opts.NoDigests)
	if err != nil {
		return nil, err
	}
	var ret []*signers.Signature
	for _, ts := range sigs {
		hash, _ := x509tools.PkixDigestToHash(ts.SignerInfo.DigestAlgorithm)
		ret = append(ret, &signers.Signature{
			Hash:          hash,
			X509Signature: ts,
		})
	}
	return ret, nil
}

func openZip(f *os.File) (*zip.Reader, error) {
	size, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		return nil, err
	}
	f.Seek(0, 0)
	return zip.NewReader(f, size)
}
