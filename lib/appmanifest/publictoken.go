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

package appmanifest

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"encoding/binary"
	"encoding/hex"
	"errors"

	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/certloader"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/x509tools"
)

func PublisherIdentity(cert *certloader.Certificate) (string, string, error) {
	issuer := cert.Issuer()
	if issuer == nil {
		return "", "", errors.New("unable to find issuer certificate in chain")
	}
	aki, err := x509tools.SubjectKeyId(issuer.PublicKey)
	if err != nil {
		return "", "", err
	}
	name := x509tools.FormatPkixName(cert.Leaf.RawSubject, x509tools.NameStyleMsOsco)
	return name, hex.EncodeToString(aki), nil
}

const (
	SnkAlgRsa       = 0x2400
	SnkAlgSha1      = 0x8004
	SnkRsaPub       = 0x06
	SnkRsaPriv      = 0x07
	SnkRsaVersion   = 0x02
	SnkRsaPubMagic  = 0x31415352
	SnkRsaPrivMagic = 0x32415352
)

type SnkHeader struct {
	PubAlgorithm  uint32
	HashAlgorithm uint32
	BlobSize      uint32
}

type SnkRsaPubKey struct {
	SnkHeader
	KeyType      uint8
	Version      uint8
	Reserved     uint16
	PubAlgorithm uint32
	KeyMagic     uint32
	BitLength    uint32
	PubExponent  uint32
}

// Calculate the publicKeyToken from a public key. This involves mangling it
// into a .snk file format, then hashing it.
//
// http://www.developerfusion.com/article/84422/the-key-to-strong-names/
func PublicKeyToken(pubKey crypto.PublicKey) (string, error) {
	snk, err := PublicKeyToSnk(pubKey)
	if err != nil {
		return "", err
	}
	d := crypto.SHA1.New()
	d.Write(snk)
	// token is the low 64 bits of sum decoded as a little-endian number, or in
	// other words the last 8 bytes in reverse order
	sum := d.Sum(nil)
	token := make([]byte, 8)
	for i := 0; i < 8; i++ {
		token[i] = sum[19-i]
	}
	return hex.EncodeToString(token), nil
}

// Convert public key to "snk" format
func PublicKeyToSnk(pubKey crypto.PublicKey) ([]byte, error) {
	var buf bytes.Buffer
	switch k := pubKey.(type) {
	case *rsa.PublicKey:
		// convert modulus to little-endian
		modulus := k.N.Bytes()
		for i := 0; i < len(modulus)/2; i++ {
			j := len(modulus) - i - 1
			modulus[i], modulus[j] = modulus[j], modulus[i]
		}
		if err := binary.Write(&buf, binary.LittleEndian, SnkRsaPubKey{
			SnkHeader: SnkHeader{
				PubAlgorithm:  SnkAlgRsa,
				HashAlgorithm: SnkAlgSha1,
				BlobSize:      uint32(20 + len(modulus)),
			},
			KeyType:      SnkRsaPub,
			Version:      SnkRsaVersion,
			PubAlgorithm: SnkAlgRsa,
			KeyMagic:     SnkRsaPubMagic,
			BitLength:    uint32(k.N.BitLen()),
			PubExponent:  uint32(k.E),
		}); err != nil {
			return nil, nil
		}
		buf.Write(modulus)
	default:
		return nil, errors.New("unsupported key type for strong name signing")
	}
	return buf.Bytes(), nil
}
