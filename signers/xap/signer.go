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

package xap

import (
	"io"
	"os"
	"path/filepath"

	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/certloader"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/signxap"
	"gerrit-pdt.unx.sas.com/tools/relic.git/signers"
	"gerrit-pdt.unx.sas.com/tools/relic.git/signers/zipbased"
)

// Sign Silverlight / legacy Windows Phone apps

var XapSigner = &signers.Signer{
	Name:      "xap",
	CertTypes: signers.CertTypeX509,
	TestPath:  testPath,
	Transform: zipbased.Transform,
	Sign:      sign,
	Verify:    verify,
}

func init() {
	signers.Register(XapSigner)
}

func testPath(fp string) bool {
	ext := filepath.Ext(fp)
	return ext == ".xap"
}

func sign(r io.Reader, cert *certloader.Certificate, opts signers.SignOpts) ([]byte, error) {
	digest, err := signxap.DigestXapTar(r, opts.Hash, false)
	if err != nil {
		return nil, err
	}
	patch, sig, err := digest.Sign(cert)
	if err != nil {
		return nil, err
	}
	opts.Audit.SetCounterSignature(sig.CounterSignature)
	return opts.SetBinPatch(patch)
}

func verify(f *os.File, opts signers.VerifyOpts) ([]*signers.Signature, error) {
	size, err := f.Seek(0, io.SeekEnd)
	sig, err := signxap.Verify(f, size, opts.NoDigests)
	if err != nil {
		return nil, err
	}
	return []*signers.Signature{&signers.Signature{
		Hash:          sig.Hash,
		X509Signature: &sig.TimestampedSignature,
	}}, nil
}
