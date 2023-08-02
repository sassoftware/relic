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

package authenticode

import (
	"context"
	"crypto"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"time"
	"unicode/utf16"

	"github.com/google/uuid"

	"github.com/sassoftware/relic/v7/lib/certloader"
	"github.com/sassoftware/relic/v7/lib/pkcs7"
	"github.com/sassoftware/relic/v7/lib/pkcs9"
	"github.com/sassoftware/relic/v7/lib/x509tools"
)

type Catalog struct {
	Version                  int
	Hash                     crypto.Hash
	Sha1Entries, Sha2Entries []CertTrustEntry
}

func NewCatalog(hash crypto.Hash) *Catalog {
	if hash == crypto.SHA1 {
		return &Catalog{Version: 1, Hash: hash}
	}
	return &Catalog{Version: 2, Hash: hash}
}

func (cat *Catalog) makeCatalog() CertTrustList {
	memberOid := OidCatalogListMember
	if cat.Version == 2 {
		memberOid = OidCatalogListMemberV2
	}
	listID := uuid.Must(uuid.NewRandom())
	return CertTrustList{
		SubjectUsage:     []asn1.ObjectIdentifier{OidCatalogList},
		ListIdentifier:   listID[:],
		EffectiveDate:    time.Now().UTC(),
		SubjectAlgorithm: pkix.AlgorithmIdentifier{Algorithm: memberOid, Parameters: asn1.NullRawValue},
		Entries:          append(cat.Sha2Entries, cat.Sha1Entries...),
	}
}

func (cat *Catalog) Marshal() ([]byte, error) {
	return asn1.Marshal(cat.makeCatalog())
}

func (cat *Catalog) Sign(ctx context.Context, cert *certloader.Certificate, params *OpusParams) (*pkcs9.TimestampedSignature, error) {
	sig := pkcs7.NewBuilder(cert.Signer(), cert.Chain(), cat.Hash)
	if err := sig.SetContent(OidCertTrustList, cat.makeCatalog()); err != nil {
		return nil, err
	}
	if err := addOpusAttrs(sig, params); err != nil {
		return nil, err
	}
	psd, err := sig.Sign()
	if err != nil {
		return nil, err
	}
	return pkcs9.TimestampAndMarshal(ctx, psd, cert.Timestamper, true)
}

func (cat *Catalog) Add(indirect SpcIndirectDataContentPe) error {
	sha2 := !indirect.MessageDigest.DigestAlgorithm.Algorithm.Equal(x509tools.OidDigestSHA1)
	if sha2 && cat.Version == 1 {
		return errors.New("can't add SHA2 digest to v1 catalog")
	}
	indirectBytes, err := asn1.Marshal(indirect)
	if err != nil {
		return err
	}
	indirectEntry := CertTrustValue{Attribute: OidSpcIndirectDataContent, Value: makeSet(indirectBytes)}
	value := indirect.MessageDigest.Digest
	if cat.Version == 1 {
		memberInfo := CertTrustMemberInfoV1{
			ClassID:  x509tools.ToBMPString(CryptSipCreateIndirectData),
			Unknown1: 512,
		}
		memberInfoEnc, err := asn1.Marshal(memberInfo)
		if err != nil {
			return err
		}
		catValue := CertTrustValue{Attribute: OidCatalogMemberInfo, Value: makeSet(memberInfoEnc)}
		cat.Sha1Entries = append(cat.Sha1Entries, CertTrustEntry{
			Tag:    tagV1(value),
			Values: []CertTrustValue{indirectEntry, catValue},
		})
	} else {
		// this supposed to always be empty?
		memberInfoEnc := []byte{0x80, 0}
		catValue := CertTrustValue{Attribute: OidCatalogMemberInfoV2, Value: makeSet(memberInfoEnc)}
		if sha2 {
			cat.Sha2Entries = append(cat.Sha2Entries, CertTrustEntry{
				Tag:    value,
				Values: []CertTrustValue{catValue, indirectEntry},
			})
		} else {
			cat.Sha1Entries = append(cat.Sha1Entries, CertTrustEntry{
				Tag:    value,
				Values: []CertTrustValue{catValue},
			})
		}
	}
	return nil
}

func tagV1(value []byte) []byte {
	// The tag is a UTF-16-LE encoding of the hex of the imprint
	runes := utf16.Encode([]rune(hex.EncodeToString(value)))
	tag := make([]byte, 2*len(runes))
	for i, r := range runes {
		binary.LittleEndian.PutUint16(tag[i*2:], r)
	}
	return tag
}

func makeSet(contents []byte) asn1.RawValue {
	return asn1.RawValue{Tag: asn1.TagSet, IsCompound: true, Bytes: contents}
}
