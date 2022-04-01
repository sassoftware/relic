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

package appmanifest

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math/big"

	"github.com/sassoftware/relic/v7/lib/certloader"
	"github.com/sassoftware/relic/v7/lib/x509tools"
)

func PublisherIdentity(cert *certloader.Certificate) (string, string, error) {
	issuer := cert.Issuer()
	if issuer == nil {
		return "", "", errors.New("unable to find issuer certificate in chain")
	}
	aki, err := x509tools.SubjectKeyID(issuer.PublicKey)
	if err != nil {
		return "", "", err
	}
	name := x509tools.FormatPkixName(cert.Leaf.RawSubject, x509tools.NameStyleMsOsco)
	return name, hex.EncodeToString(aki), nil
}

const (
	snkRsaPub     = 0x06
	snkRsaVersion = 0x02
	// https://msdn.microsoft.com/en-us/library/windows/desktop/aa375549(v=vs.85).aspx
	calgRsaSign = 0x2400 // CALG_RSA_SIGN
	calgSha1    = 0x8004 // CALG_SHA1
	calgEcdsa   = 0x2203 // CALG_ECDSA
	// bcrypt.h
	bcryptRsaPubMagic  = 0x31415352 // BCRYPT_RSAPUBLIC_MAGIC
	bcryptEcdsaPubP256 = 0x31534345 // BCRYPT_ECDSA_PUBLIC_P256_MAGIC
	bcryptEcdsaPubP384 = 0x33534345 // BCRYPT_ECDSA_PUBLIC_P384_MAGIC
	bcryptEcdsaPubP521 = 0x35534345 // BCRYPT_ECDSA_PUBLIC_P521_MAGIC
)

type snkHeader struct {
	PubAlgorithm  uint32
	HashAlgorithm uint32
	BlobSize      uint32
	KeyType       uint8
	Version       uint8
	Reserved      uint16
	PubAlgorithm2 uint32
}

type blobRsaPub struct {
	snkHeader
	// BCRYPT_RSAKEY_BLOB
	KeyMagic    uint32
	BitLength   uint32
	PubExponent uint32
} // N [BitLength/8]byte

type blobEcdsaPub struct {
	snkHeader
	// BCRYPT_ECCKEY_BLOB
	KeyMagic   uint32
	ByteLength uint32
} // X, Y [ByteLength]byte

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
		modulus := bigIntToLE(k.N)
		if err := binary.Write(&buf, binary.LittleEndian, blobRsaPub{
			snkHeader: snkHeader{
				PubAlgorithm:  calgRsaSign,
				HashAlgorithm: calgSha1,
				BlobSize:      uint32(20 + len(modulus)),
				KeyType:       snkRsaPub,
				Version:       snkRsaVersion,
				PubAlgorithm2: calgRsaSign,
			},
			KeyMagic:    bcryptRsaPubMagic,
			BitLength:   uint32(8 * len(modulus)),
			PubExponent: uint32(k.E),
		}); err != nil {
			return nil, nil
		}
		buf.Write(modulus)
	case *ecdsa.PublicKey:
		// TODO: This is a best guess based on piecing together various
		// Microsoft documentation and header values, but some pieces are still
		// missing. ECDSA isn't supported for strong name signing, and
		// calcuating the publicKeyToken for SN is the only reason this
		// function is even here.
		var keyMagic uint32
		switch k.Curve {
		case elliptic.P256():
			keyMagic = bcryptEcdsaPubP256
		case elliptic.P384():
			keyMagic = bcryptEcdsaPubP384
		case elliptic.P521():
			keyMagic = bcryptEcdsaPubP521
		default:
			return nil, errors.New("unsupported ECDSA curve")
		}
		// TODO: are these supposed to be big-endian? the documentation for
		// BCRYPT_ECCKEY_BLOB says so, but it also said that about the RSA one
		// and yet the SNK format actually uses little endian...
		x := k.X.Bytes()
		y := k.Y.Bytes()
		if err := binary.Write(&buf, binary.LittleEndian, blobEcdsaPub{
			snkHeader: snkHeader{
				PubAlgorithm:  calgEcdsa,
				HashAlgorithm: calgSha1,
				BlobSize:      uint32(12 + 2*len(x)),
				KeyType:       snkRsaPub,     // TODO
				Version:       snkRsaVersion, // TODO
				PubAlgorithm2: calgEcdsa,
			},
			KeyMagic:   keyMagic,
			ByteLength: uint32(len(x)),
		}); err != nil {
			return nil, nil
		}
		buf.Write(x)
		buf.Write(y)
	default:
		return nil, errors.New("unsupported key type for strong name signing")
	}
	return buf.Bytes(), nil
}

func bigIntToLE(x *big.Int) []byte {
	b := x.Bytes()
	for i := 0; i < len(b)/2; i++ {
		j := len(b) - i - 1
		b[i], b[j] = b[j], b[i]
	}
	return b
}
