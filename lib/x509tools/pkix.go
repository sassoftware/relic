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
	"crypto/x509/pkix"
	"encoding/asn1"
)

var (
	// RFC 3279
	OidDigestMD5  = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 5}
	OidDigestSHA1 = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	// RFC 5758
	OidDigestSHA224 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 4}
	OidDigestSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	OidDigestSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	OidDigestSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}

	// RFC 3279
	OidPublicKeyRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	OidPublicKeyDSA   = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 1}
	OidPublicKeyECDSA = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}

	Asn1TagNull      = 5
	Asn1TagBMPString = 30
)

var Asn1Null = asn1.RawValue{Tag: Asn1TagNull}

var HashOids = map[crypto.Hash]asn1.ObjectIdentifier{
	crypto.MD5:    OidDigestMD5,
	crypto.SHA1:   OidDigestSHA1,
	crypto.SHA224: OidDigestSHA224,
	crypto.SHA256: OidDigestSHA256,
	crypto.SHA384: OidDigestSHA384,
	crypto.SHA512: OidDigestSHA512,
}

var HashNames = map[crypto.Hash]string{
	crypto.MD5:    "MD5",
	crypto.SHA1:   "SHA1",
	crypto.SHA224: "SHA-224",
	crypto.SHA256: "SHA-256",
	crypto.SHA384: "SHA-384",
	crypto.SHA512: "SHA-512",
}

// Convert a crypto.Hash to a X.509 AlgorithmIdentifier
func PkixDigestAlgorithm(hash crypto.Hash) (alg pkix.AlgorithmIdentifier, ok bool) {
	if oid, ok2 := HashOids[hash]; ok2 {
		alg.Algorithm = oid
		// some implementations want this to be NULL, not missing entirely
		alg.Parameters = Asn1Null
		ok = true
	}
	return
}

// Convert a X.509 AlgorithmIdentifier to a crypto.Hash
func PkixDigestToHash(alg pkix.AlgorithmIdentifier) (hash crypto.Hash, ok bool) {
	for hash, oid := range HashOids {
		if alg.Algorithm.Equal(oid) {
			return hash, true
		}
	}
	return 0, false
}

// Convert a crypto.PublicKey to a X.509 AlgorithmIdentifier
func PkixPublicKeyAlgorithm(pub crypto.PublicKey) (alg pkix.AlgorithmIdentifier, ok bool) {
	switch pub.(type) {
	case *rsa.PublicKey:
		alg.Algorithm = OidPublicKeyRSA
	case *ecdsa.PublicKey:
		alg.Algorithm = OidPublicKeyECDSA
	default:
		return
	}
	// openssl expects this to be NULL, not missing entirely
	alg.Parameters = asn1.RawValue{Tag: 5}
	return alg, true
}

type digestInfo struct {
	DigestAlgorithm pkix.AlgorithmIdentifier
	Digest          []byte
}

// Pack a digest along with an algorithm identifier. Mainly useful for
// PKCS#1v1.5 padding (RSA).
func MarshalDigest(hash crypto.Hash, digest []byte) (der []byte, ok bool) {
	alg, ok := PkixDigestAlgorithm(hash)
	if !ok {
		return nil, false
	}
	der, err := asn1.Marshal(digestInfo{alg, digest})
	if err != nil {
		return nil, false
	}
	return der, true
}
