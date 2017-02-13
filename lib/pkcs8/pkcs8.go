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

func MarshalPKCS8PrivateKey(priv crypto.PrivateKey) ([]byte, error) {
	switch pkey := priv.(type) {
	case *rsa.PrivateKey:
		return asn1.Marshal(privateKeyInfo{
			Version: 0,
			PrivateKeyAlgorithm: pkix.AlgorithmIdentifier{
				x509tools.OidPublicKeyRSA,
				asn1.RawValue{Tag: 5},
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
