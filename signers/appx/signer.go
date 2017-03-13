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

package appx

// Sign Windows Universal (UWP) .appx and .appxbundle

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"

	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/binpatch"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/certloader"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/signappx"
	"gerrit-pdt.unx.sas.com/tools/relic.git/signers"
	//"gerrit-pdt.unx.sas.com/tools/relic.git/signers/pkcs"
)

var AppxSigner = &signers.Signer{
	Name:      "appx",
	CertTypes: signers.CertTypeX509,
	TestPath:  testPath,
	Transform: transform,
	Sign:      sign,
	Verify:    verify,
}

func init() {
	signers.Register(AppxSigner)
}

func testPath(filepath string) bool {
	ext := path.Ext(filepath)
	return ext == ".appx" || ext == ".appxbundle"
}

type appxTransformer struct {
	f *os.File
}

func transform(f *os.File, opts signers.SignOpts) (signers.Transformer, error) {
	return &appxTransformer{f}, nil
}

func (t *appxTransformer) GetReader() (io.Reader, int64, error) {
	r, w := io.Pipe()
	go func() {
		w.CloseWithError(signappx.AppxToTar(t.f, w))
	}()
	return r, -1, nil
}

func (t *appxTransformer) Apply(dest, mimeType string, result io.Reader) error {
	blob, err := ioutil.ReadAll(result)
	if err != nil {
		return err
	}
	patch, err := binpatch.Load(blob)
	if err != nil {
		return err
	}
	return patch.Apply(t.f, dest)
}

func sign(r io.Reader, cert *certloader.Certificate, opts signers.SignOpts) ([]byte, error) {
	digest, err := signappx.DigestAppxTar(r, opts.Hash, false)
	if err != nil {
		return nil, err
	}
	patch, priSig, _, err := digest.Sign(cert)
	if err != nil {
		return nil, err
	}
	opts.Audit.SetCounterSignature(priSig.CounterSignature)
	return opts.SetBinPatch(patch)
}

func verify(f *os.File, opts signers.VerifyOpts) ([]*signers.Signature, error) {
	size, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		return nil, err
	}
	sig, err := signappx.Verify(f, size, opts.NoDigests)
	if err != nil {
		return nil, err
	}
	appxSig := sig
	if sig.IsBundle {
		for _, nested := range sig.Bundled {
			appxSig = nested
			break
		}
	}
	return []*signers.Signature{&signers.Signature{
		Package:       fmt.Sprintf("{%s} %s %s", appxSig.Name, appxSig.DisplayName, appxSig.Version),
		Hash:          sig.Hash,
		X509Signature: sig.Signature,
	}}, nil
	return nil, nil
}
