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

package appmanifest

// Sign Microsoft ClickOnce application manifests and deployment manifests.
// These take the form of an XML file using XML DSIG signatures and, unlike all
// other Microsoft signatures, does not use an Authenticode PKCS#7 structure.

import (
	"fmt"
	"io"
	"io/ioutil"

	"github.com/rs/zerolog"
	"github.com/sassoftware/relic/v7/lib/appmanifest"
	"github.com/sassoftware/relic/v7/lib/audit"
	"github.com/sassoftware/relic/v7/lib/certloader"
	"github.com/sassoftware/relic/v7/lib/magic"
	"github.com/sassoftware/relic/v7/lib/pkcs9"
	"github.com/sassoftware/relic/v7/signers"
)

var AppSigner = &signers.Signer{
	Name:         "appmanifest",
	Magic:        magic.FileTypeAppManifest,
	CertTypes:    signers.CertTypeX509,
	FormatLog:    formatLog,
	Sign:         sign,
	VerifyStream: verify,
}

func init() {
	AppSigner.Flags().Bool("rfc3161-timestamp", true, "(APPMANIFEST) Timestamp with RFC3161 server")
	signers.Register(AppSigner)
}

func formatLog(info *audit.Info) *zerolog.Event {
	return info.AttrsForLog("assembly.")
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
	if cert.Timestamper != nil {
		tsreq := &pkcs9.Request{
			EncryptedDigest: signed.EncryptedDigest,
			Legacy:          !opts.Flags.GetBool("rfc3161-timestamp"),
			Hash:            opts.Hash,
		}

		token, err := cert.Timestamper.Timestamp(opts.Context(), tsreq)
		if err != nil {
			return nil, err
		}
		if err := signed.AddTimestamp(token); err != nil {
			return nil, err
		}
	}
	opts.Audit.SetMimeType("application/xml")
	opts.Audit.Attributes["assembly.name"] = signed.AssemblyName
	opts.Audit.Attributes["assembly.version"] = signed.AssemblyVersion
	opts.Audit.Attributes["assembly.publicKeyToken"] = signed.PublicKeyToken
	opts.Audit.SetCounterSignature(signed.Signature.CounterSignature)
	return signed.Signed, nil
}

func verify(r io.Reader, opts signers.VerifyOpts) ([]*signers.Signature, error) {
	blob, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}
	sig, err := appmanifest.Verify(blob)
	if err != nil {
		return nil, err
	}
	return []*signers.Signature{&signers.Signature{
		Package:       fmt.Sprintf("%s %s", sig.AssemblyName, sig.AssemblyVersion),
		Hash:          sig.Hash,
		X509Signature: sig.Signature,
	}}, nil
}
