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
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
)

// Parse a private key from a blob of PEM data
func ParsePEMPrivateKey(pemData []byte) (crypto.PrivateKey, error) {
	var keyBlock *pem.Block
	for {
		keyBlock, pemData = pem.Decode(pemData)
		if keyBlock == nil {
			return nil, errors.New("failed to find any private keys in PEM data")
		}
		if keyBlock.Type == "PRIVATE KEY" || strings.HasSuffix(keyBlock.Type, " PRIVATE KEY") {
			return ParsePrivateKey(keyBlock.Bytes)
		}
	}
}

// Parse a private key from a DER block
// See crypto/tls.parsePrivateKey
func ParsePrivateKey(der []byte) (crypto.PrivateKey, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey:
			return key, nil
		default:
			return nil, errors.New("tls: found unknown private key type in PKCS#8 wrapping")
		}
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}

	return nil, errors.New("tls: failed to parse private key")
}
