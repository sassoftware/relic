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

// PKCS#8 is a specification for encoding private keys into an ASN.1 structure.
// See RFC 5208
//
// The Go standard library implements parsing PKCS#8 keys but does not support
// marshalling them; this module provides that function.
package pkcs8

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"

	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/x509tools"
)

type privateKeyInfo struct {
	Version             int
	PrivateKeyAlgorithm pkix.AlgorithmIdentifier
	PrivateKey          []byte
}

// Marshal a RSA or ECDSA private key as an unencrypted PKCS#8 blob
func MarshalPKCS8PrivateKey(priv crypto.PrivateKey) ([]byte, error) {
	switch pkey := priv.(type) {
	case *rsa.PrivateKey:
		return asn1.Marshal(privateKeyInfo{
			Version: 0,
			PrivateKeyAlgorithm: pkix.AlgorithmIdentifier{
				x509tools.OidPublicKeyRSA,
				x509tools.Asn1Null,
			},
			PrivateKey: x509.MarshalPKCS1PrivateKey(pkey),
		})
	case *ecdsa.PrivateKey:
		curve, err := x509tools.CurveByCurve(pkey.Curve)
		if err != nil {
			return nil, err
		}
		eckey, err := x509.MarshalECPrivateKey(pkey)
		if err != nil {
			return nil, err
		}
		return asn1.Marshal(privateKeyInfo{
			Version: 0,
			PrivateKeyAlgorithm: pkix.AlgorithmIdentifier{
				x509tools.OidPublicKeyECDSA,
				asn1.RawValue{FullBytes: curve.ToDer()},
			},
			PrivateKey: eckey,
		})
	default:
		return nil, errors.New("unsupported key type")
	}
}
