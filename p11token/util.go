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

package p11token

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"math/big"
)

func makeKeyId() []byte {
	keyId := make([]byte, 20)
	if n, err := rand.Reader.Read(keyId); err != nil || n != 20 {
		return nil
	}
	return keyId
}

func parseKeyId(value string) ([]byte, error) {
	return hex.DecodeString(value)
}

func bytesToBig(val []byte) *big.Int {
	return new(big.Int).SetBytes(val)
}

func SameKey(pub1, pub2 interface{}) bool {
	switch key1 := pub1.(type) {
	case *rsa.PublicKey:
		key2, ok := pub2.(*rsa.PublicKey)
		return ok && key1.E == key2.E && key1.N.Cmp(key2.N) == 0
	case *ecdsa.PublicKey:
		key2, ok := pub2.(*ecdsa.PublicKey)
		return ok && key1.X.Cmp(key2.X) == 0 && key1.Y.Cmp(key2.Y) == 0
	default:
		return false
	}
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
