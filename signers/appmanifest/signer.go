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
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/appmanifest"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/audit"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/certloader"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/magic"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/pkcs7"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/pkcs9"
	"gerrit-pdt.unx.sas.com/tools/relic.git/signers"
)

var AppSigner = &signers.Signer{
	Name:      "appmanifest",
	Magic:     magic.FileTypeAppManifest,
	CertTypes: signers.CertTypeX509,
	FormatLog: formatLog,
	Sign:      sign,
	Verify:    verify,
}

func init() {
	signers.Register(AppSigner)
}

func formatLog(info *audit.AuditInfo) string {
	return fmt.Sprintf("assembly=%s version=%s publicKeyToken=%s",
		info.Attributes["assembly.name"],
		info.Attributes["assembly.version"],
		info.Attributes["assembly.publicKeyToken"],
	)
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
	opts.Audit.Attributes["assembly.name"] = signed.AssemblyName
	opts.Audit.Attributes["assembly.version"] = signed.AssemblyVersion
	opts.Audit.Attributes["assembly.publicKeyToken"] = signed.PublicKeyToken
	return signed.Signed, nil
}

func verify(f *os.File, opts signers.VerifyOpts) ([]*signers.Signature, error) {
	blob, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}
	sig, err := appmanifest.Verify(blob)
	if err != nil {
		return nil, err
	}
	return []*signers.Signature{&signers.Signature{
		Package: fmt.Sprintf("%s %s", sig.AssemblyName, sig.AssemblyVersion),
		Hash:    sig.Hash,
		X509Signature: &pkcs9.TimestampedSignature{
			Signature: pkcs7.Signature{
				Certificate:   sig.Leaf,
				Intermediates: sig.Certificates,
			},
		},
	}}, nil
}
