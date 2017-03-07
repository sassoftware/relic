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

package appmanifest

// Sign Microsoft ClickOnce application manifests and deployment manifests.
// These take the form of an XML file using XML DSIG signatures and, unlike all
// other Microsoft signatures, does not use an Authenticode PKCS#7 structure.

import (
	"errors"
	"io"
	"io/ioutil"
	"os"

	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/appmanifest"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/certloader"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/magic"
	"gerrit-pdt.unx.sas.com/tools/relic.git/signers"
)

var AppSigner = &signers.Signer{
	Name:      "appmanifest",
	Magic:     magic.FileTypeAppManifest,
	CertTypes: signers.CertTypeX509,
	Sign:      sign,
	Verify:    verify,
}

func init() {
	signers.Register(AppSigner)
}

func sign(r io.Reader, cert *certloader.Certificate, opts signers.SignOpts) ([]byte, error) {
	blob, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}
	signed, err := appmanifest.Sign(blob, cert, opts.Hash)
	if err != nil {
		return nil, err
	}
	opts.Audit.SetMimeType("application/xml")
	return signed.Signed, nil
}

func verify(f *os.File, opts signers.VerifyOpts) ([]*signers.Signature, error) {
	return nil, errors.New("verifying app manifests is not implemented yet")
}
