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
	"errors"

	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/comdoc"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/pkcs7"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/x509tools"
)

func SignMSIImprint(digest []byte, hash crypto.Hash, privKey crypto.Signer, certs []*x509.Certificate) (*pkcs7.ContentInfoSignedData, error) {
	alg, ok := x509tools.PkixDigestAlgorithm(hash)
	if !ok {
		return nil, errors.New("unsupported digest algorithm")
	}
	var indirect SpcIndirectDataContentMsi
	indirect.Data.Type = OidSpcSipInfo
	indirect.Data.Value = defaultSipInfo
	indirect.MessageDigest.Digest = digest
	indirect.MessageDigest.DigestAlgorithm = alg
	sig := pkcs7.NewBuilder(privKey, certs, hash)
	if err := sig.SetContent(OidSpcIndirectDataContent, indirect); err != nil {
		return nil, err
	}
	if err := sig.AddAuthenticatedAttribute(OidSpcSpOpusInfo, SpcSpOpusInfo{}); err != nil {
		return nil, err
	}
	return sig.Sign()
}

func InsertMSISignature(cdf *comdoc.ComDoc, pkcs, exsig []byte) error {
	if len(exsig) > 0 {
		if err := cdf.AddFile(msiDigitalSignatureEx, exsig); err != nil {
			return err
		}
	} else {
		if err := cdf.DeleteFile(msiDigitalSignatureEx); err != nil {
			return err
		}
	}
	return cdf.AddFile(msiDigitalSignature, pkcs)
}
