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

package pkcs7

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"

	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/x509tools"
)

func SignData(content []byte, privKey crypto.Signer, certs []*x509.Certificate, opts crypto.SignerOpts) (*ContentInfoSignedData, error) {
	hash := opts.HashFunc().New()
	hash.Write(content)
	cinfo, err := NewContentInfo(OidData, content)
	if err != nil {
		return nil, err
	}
	return signData(cinfo, hash.Sum(nil), privKey, certs, opts)
}

func SignDetached(digest []byte, privKey crypto.Signer, certs []*x509.Certificate, opts crypto.SignerOpts) (*ContentInfoSignedData, error) {
	cinfo, _ := NewContentInfo(OidData, nil)
	return signData(cinfo, digest, privKey, certs, opts)
}

func signData(cinfo ContentInfo, digest []byte, privKey crypto.Signer, certs []*x509.Certificate, opts crypto.SignerOpts) (*ContentInfoSignedData, error) {
	digestAlg, ok := x509tools.PkixDigestAlgorithm(opts.HashFunc())
	if !ok {
		return nil, errors.New("pkcs7: unsupported digest algorithm")
	}
	pubKey := privKey.Public()
	pkeyAlg, ok := x509tools.PkixPublicKeyAlgorithm(pubKey)
	if !ok {
		return nil, errors.New("pkcs7: unsupported public key algorithm")
	}
	if _, ok := opts.(*rsa.PSSOptions); ok {
		return nil, errors.New("pkcs7: RSA-PSS not implemented")
	}
	if len(certs) < 1 || !x509tools.SameKey(pubKey, certs[0].PublicKey) {
		return nil, errors.New("pkcs7: first certificate must match private key")
	}
	sig, err := privKey.Sign(rand.Reader, digest, opts)
	if err != nil {
		return nil, err
	}
	return &ContentInfoSignedData{
		ContentType: OidSignedData,
		Content: SignedData{
			Version:                    1,
			DigestAlgorithmIdentifiers: []pkix.AlgorithmIdentifier{digestAlg},
			ContentInfo:                cinfo,
			Certificates:               MarshalCertificates(certs),
			CRLs:                       nil,
			SignerInfos: []SignerInfo{SignerInfo{
				Version: 1,
				IssuerAndSerialNumber: IssuerAndSerial{
					IssuerName:   asn1.RawValue{FullBytes: certs[0].RawIssuer},
					SerialNumber: certs[0].SerialNumber,
				},
				DigestAlgorithm:           digestAlg,
				DigestEncryptionAlgorithm: pkeyAlg,
				EncryptedDigest:           sig,
			}},
		},
	}, nil
}

func MarshalCertificates(certs []*x509.Certificate) RawCertificates {
	var buf bytes.Buffer
	for _, cert := range certs {
		buf.Write(cert.Raw)
	}
	val := asn1.RawValue{Bytes: buf.Bytes(), Class: 2, Tag: 0, IsCompound: true}
	b, _ := asn1.Marshal(val)
	return RawCertificates{Raw: b}
}

func (raw RawCertificates) Parse() ([]*x509.Certificate, error) {
	var val asn1.RawValue
	if len(raw.Raw) == 0 {
		return nil, nil
	}
	if _, err := asn1.Unmarshal(raw.Raw, &val); err != nil {
		return nil, err
	}
	return x509.ParseCertificates(val.Bytes)
}
