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

package apk

import (
	"crypto"
	"crypto/x509"
	"fmt"
)

type apkSigner struct {
	SignedData apkRaw
	Signatures []apkSignature
	PublicKey  []byte
}

type apkSignedData struct {
	Digests      []apkDigest
	Certificates [][]byte
	Attributes   []apkAttribute
}

type apkAttribute struct {
	ID    uint32
	Value []byte
}

type apkSignature apkAttribute
type apkDigest apkAttribute

func (sd *apkSignedData) ParseCertificates() (certs []*x509.Certificate, err error) {
	certs = make([]*x509.Certificate, len(sd.Certificates))
	for i, der := range sd.Certificates {
		certs[i], err = x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
	}
	return
}

type sigType struct {
	id   uint32
	hash crypto.Hash
	alg  x509.PublicKeyAlgorithm
	pss  bool
}

var sigTypes = []sigType{
	sigType{0x0101, crypto.SHA256, x509.RSA, true},    // RSASSA-PSS with SHA2-256 digest
	sigType{0x0102, crypto.SHA512, x509.RSA, true},    // RSASSA-PSS with SHA2-512 digest
	sigType{0x0103, crypto.SHA256, x509.RSA, false},   // RSASSA-PKCS1-v1_5 with SHA2-256 digest
	sigType{0x0104, crypto.SHA512, x509.RSA, false},   // RSASSA-PKCS1-v1_5 with SHA2-512 digest
	sigType{0x0201, crypto.SHA256, x509.ECDSA, false}, // ECDSA with SHA2-256 digest
	sigType{0x0202, crypto.SHA512, x509.ECDSA, false}, // ECDSA with SHA2-512 digest
	sigType{0x0301, crypto.SHA256, x509.DSA, false},   // DSA with SHA2-256 digest
}

func sigTypeByID(id uint32) (st sigType, err error) {
	for _, s := range sigTypes {
		if s.id == id {
			st = s
			break
		}
	}
	if st.id == 0 {
		return st, fmt.Errorf("unknown signature type 0x%04x", id)
	}
	if !st.hash.Available() {
		return st, fmt.Errorf("unsupported signature type 0x%04x", id)
	}
	return
}
