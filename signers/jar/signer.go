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

import (
	"archive/zip"
	"bytes"
	"errors"
	"io"
	"io/ioutil"
	"os"

	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/atomicfile"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/certloader"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/magic"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/pkcs7"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/signjar"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/x509tools"
	"gerrit-pdt.unx.sas.com/tools/relic.git/signers"
	"gerrit-pdt.unx.sas.com/tools/relic.git/signers/pkcs"
)

var JarSigner = &signers.Signer{
	Name:      "jar",
	Magic:     magic.FileTypeJAR,
	CertTypes: signers.CertTypeX509,
	Transform: transform,
	Sign:      sign,
	Verify:    verify,
}

func init() {
	JarSigner.Flags().Bool("sections-only", false, "(JAR) Don't compute hash of entire manifest")
	JarSigner.Flags().Bool("inline-signature", false, "(JAR) Include .SF inside the signature block")
	JarSigner.Flags().String("key-alias", "RELIC", "(JAR) Alias to use for the signed manifest")
	signers.Register(JarSigner)
}

type jarTransformer struct {
	f               *os.File
	inz             *zip.Reader
	manifest        []byte
	inlineSignature bool
	alias           string
}

func transform(f *os.File, opts signers.SignOpts) (signers.Transformer, error) {
	argInlineSignature, _ := opts.Flags.GetBool("inline-signature")
	argAlias, _ := opts.Flags.GetString("key-alias")
	inz, err := openZip(f)
	if err != nil {
		return nil, err
	}
	manifest, err := signjar.DigestJar(inz, opts.Hash)
	if err != nil {
		return nil, err
	}
	return &jarTransformer{f, inz, manifest, argInlineSignature, argAlias}, nil
}

func (t *jarTransformer) GetReader() (io.Reader, int64, error) {
	return bytes.NewReader(t.manifest), int64(len(t.manifest)), nil
}

func (t *jarTransformer) Apply(dest, mimeType string, result io.Reader) error {
	blob, err := ioutil.ReadAll(result)
	if err != nil {
		return err
	}
	// need the public key to determine how to name the signature (.RSA or .EC)
	certs, err := pkcs7.ParseCertificates(blob)
	if err != nil {
		return err
	} else if len(certs) == 0 {
		return errors.New("pkcs7: did not contain any certificates")
	}
	pubkey := certs[0].PublicKey
	// detach the .SF content from the signature unless --inline-signature is set
	detached, sigfile, err := pkcs7.ExtractAndDetach(blob)
	if err != nil {
		return err
	}
	if !t.inlineSignature {
		blob = detached
	}
	// write updated JAR
	w, err := atomicfile.WriteAny(dest)
	if err != nil {
		return err
	}
	defer w.Close()
	if err := signjar.UpdateJar(w, t.inz, t.alias, pubkey, t.manifest, sigfile, blob); err != nil {
		return err
	}
	t.f.Close()
	return w.Commit()
}

// sign a manifest and return the PKCS#7 blob
func sign(r io.Reader, cert *certloader.Certificate, opts signers.SignOpts) ([]byte, error) {
	argSectionsOnly, _ := opts.Flags.GetBool("sections-only")
	manifest, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}
	sigfile, err := signjar.DigestManifest(manifest, opts.Hash, argSectionsOnly)
	if err != nil {
		return nil, err
	}
	psd, err := pkcs7.SignData(sigfile, cert.Signer(), cert.Chain(), opts.Hash)
	if err != nil {
		return nil, err
	}
	return pkcs.Timestamp(psd, cert, opts, false)
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
