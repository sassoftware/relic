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

package authenticode

import (
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"errors"

	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/pkcs7"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/x509tools"
)

func makePeIndirect(imprint []byte, hash crypto.Hash, oid asn1.ObjectIdentifier) (indirect SpcIndirectDataContentPe, err error) {
	alg, ok := x509tools.PkixDigestAlgorithm(hash)
	if !ok {
		err = errors.New("unsupported digest algorithm")
		return
	}
	indirect.Data.Type = oid
	indirect.MessageDigest.Digest = imprint
	indirect.MessageDigest.DigestAlgorithm = alg
	indirect.Data.Value.File.File.Unicode = "<<<Obsolete>>>"
	return
}

func signIndirect(indirect interface{}, hash crypto.Hash, privKey crypto.Signer, certs []*x509.Certificate) (*pkcs7.ContentInfoSignedData, error) {
	sig := pkcs7.NewBuilder(privKey, certs, hash)
	if err := sig.SetContent(OidSpcIndirectDataContent, indirect); err != nil {
		return nil, err
	}
	if err := addOpusAttrs(sig); err != nil {
		return nil, err
	}
	return sig.Sign()
}

func addOpusAttrs(sig *pkcs7.SignatureBuilder) error {
	if err := sig.AddAuthenticatedAttribute(OidSpcStatementType, SpcSpStatementType{Type: OidSpcIndividualPurpose}); err != nil {
		return err
	}
	if err := sig.AddAuthenticatedAttribute(OidSpcSpOpusInfo, SpcSpOpusInfo{}); err != nil {
		return err
	}
	return nil
}

func SignSip(imprint []byte, hash crypto.Hash, sipInfo SpcSipInfo, privKey crypto.Signer, certs []*x509.Certificate) (*pkcs7.ContentInfoSignedData, error) {
	alg, ok := x509tools.PkixDigestAlgorithm(hash)
	if !ok {
		return nil, errors.New("unsupported digest algorithm")
	}
	var indirect SpcIndirectDataContentMsi
	indirect.Data.Type = OidSpcSipInfo
	indirect.Data.Value = sipInfo
	indirect.MessageDigest.Digest = imprint
	indirect.MessageDigest.DigestAlgorithm = alg
	return signIndirect(indirect, hash, privKey, certs)
}
