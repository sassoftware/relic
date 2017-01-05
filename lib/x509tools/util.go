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

package x509tools

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
)

func MakeSerial() *big.Int {
	blob := make([]byte, 12)
	if n, err := rand.Reader.Read(blob); err != nil || n != len(blob) {
		return nil
	}
	return new(big.Int).SetBytes(blob)
}

func X509SignatureAlgorithm(pub crypto.PublicKey) x509.SignatureAlgorithm {
	switch pub.(type) {
	case *rsa.PublicKey:
		return x509.SHA256WithRSA
	case *ecdsa.PublicKey:
		return x509.ECDSAWithSHA256
	default:
		return x509.UnknownSignatureAlgorithm
	}
}

type pkixPublicKey struct {
	Algo      pkix.AlgorithmIdentifier
	BitString asn1.BitString
}

func SubjectKeyId(pub crypto.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	// extract the raw "bit string" part of the public key bytes
	var pki pkixPublicKey
	if rest, err := asn1.Unmarshal(der, &pki); err != nil {
		return nil, err
	} else if len(rest) != 0 {
		return nil, errors.New("trailing garbage on public key")
	}
	digest := sha256.Sum256(pki.BitString.Bytes)
	return digest[:], nil
}
