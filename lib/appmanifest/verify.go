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

import (
	"crypto"
	"encoding/base64"
	"errors"
	"fmt"

	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/pkcs7"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/pkcs9"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/x509tools"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/xmldsig"
	"github.com/beevik/etree"
)

type ManifestSignature struct {
	Signature       *pkcs9.TimestampedSignature
	Hash            crypto.Hash
	AssemblyName    string
	AssemblyVersion string
	PublicKeyToken  string
}

// Extract and verify signature on an application manifest. Does not verify X509 chains.
func Verify(manifest []byte) (*ManifestSignature, error) {
	doc := etree.NewDocument()
	if err := doc.ReadFromString(string(manifest)); err != nil {
		return nil, err
	}
	root := doc.Root()
	primary, err := xmldsig.Verify(root, "Signature")
	if err != nil {
		return nil, fmt.Errorf("invalid primary signature: %s", err)
	}
	license := root.FindElement("Signature/KeyInfo/msrel:RelData/r:license")
	if license == nil {
		return nil, fmt.Errorf("invalid authenticode signature: %s", "signature is missing")
	}
	secondary, err := xmldsig.Verify(license, "issuer/Signature")
	if err != nil {
		return nil, fmt.Errorf("invalid authenticode signature: %s", err)
	}
	if !x509tools.SameKey(primary.PublicKey, secondary.PublicKey) {
		return nil, errors.New("signatures were made with different keys")
	}
	asi := root.SelectElement("assemblyIdentity")
	if asi == nil {
		return nil, errors.New("missing assemblyIdentity")
	}
	token, err := PublicKeyToken(primary.PublicKey)
	if err != nil {
		return nil, err
	}
	if token2 := asi.SelectAttrValue("publicKeyToken", ""); token2 != token {
		return nil, fmt.Errorf("publicKeyToken mismatch: expected %s, got %s", token, token2)
	}
	sig := pkcs7.Signature{Intermediates: secondary.Certificates}
	for _, cert := range secondary.Certificates {
		if x509tools.SameKey(cert.PublicKey, primary.PublicKey) {
			sig.Certificate = cert
			break
		}
	}
	if sig.Certificate == nil {
		return nil, errors.New("leaf x509 certificate not found")
	}
	ts := &pkcs9.TimestampedSignature{Signature: sig}
	if tse := license.FindElement("r:issuer/Signature/Object/as:Timestamp"); tse != nil {
		blob, err := base64.StdEncoding.DecodeString(tse.Text())
		if err != nil {
			return nil, fmt.Errorf("invalid timestamp: %s", err)
		}
		timestamp, err := pkcs7.Unmarshal(blob)
		if err != nil {
			return nil, fmt.Errorf("invalid timestamp: %s", err)
		}
		cs, err := pkcs9.VerifyMicrosoftToken(timestamp, secondary.EncryptedDigest)
		if err != nil {
			return nil, fmt.Errorf("invalid timestamp: %s", err)
		}
		ts.CounterSignature = cs
	}
	return &ManifestSignature{
		Signature:       ts,
		AssemblyName:    asi.SelectAttrValue("name", ""),
		AssemblyVersion: asi.SelectAttrValue("version", ""),
		Hash:            primary.Hash,
		PublicKeyToken:  token,
	}, nil
}
