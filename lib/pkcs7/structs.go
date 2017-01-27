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

package pkcs7

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
)

var (
	OidData                   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	OidSignedData             = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	OidAttributeContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	OidAttributeMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	OidAttributeSigningTime   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
)

type ContentInfo struct {
	Raw         asn1.RawContent
	ContentType asn1.ObjectIdentifier
}

type ContentInfoSignedData struct {
	ContentType asn1.ObjectIdentifier
	Content     SignedData `asn1:"explicit,optional,tag:0"`
}

type SignedData struct {
	Version                    int                        `asn1:"default:1"`
	DigestAlgorithmIdentifiers []pkix.AlgorithmIdentifier `asn1:"set"`
	ContentInfo                ContentInfo                ``
	Certificates               RawCertificates            `asn1:"optional,tag:0"`
	CRLs                       []pkix.CertificateList     `asn1:"optional,tag:1"`
	SignerInfos                []SignerInfo               `asn1:"set"`
}

type RawCertificates struct {
	Raw asn1.RawContent
}

type Attribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue
}

type AttributeList []Attribute

func (l *AttributeList) GetOne(oid asn1.ObjectIdentifier, dest interface{}) error {
	for _, raw := range *l {
		if !raw.Type.Equal(oid) {
			continue
		}
		rest, err := asn1.Unmarshal(raw.Values.Bytes, dest)
		if err != nil {
			return err
		} else if len(rest) != 0 {
			return fmt.Errorf("attribute %s: expected one, found multiple", oid)
		} else {
			return nil
		}
	}
	return fmt.Errorf("attribute not found: %s", oid)
}

// marshal authenticated attributes for digesting
func (l *AttributeList) Bytes() ([]byte, error) {
	// needs an explicit SET OF tag but not the class-specific tag from the
	// original struct. see RFC 2315 9.3, 2nd paragraph
	encoded, err := asn1.Marshal(struct {
		A []Attribute `asn1:"set"`
	}{A: *l})
	if err != nil {
		return nil, err
	}
	var raw asn1.RawValue
	if _, err := asn1.Unmarshal(encoded, &raw); err != nil {
		return nil, err
	}
	return raw.Bytes, nil
}

func (l *AttributeList) Add(oid asn1.ObjectIdentifier, obj interface{}) error {
	value, err := asn1.Marshal(obj)
	if err != nil {
		return err
	}
	for _, attr := range *l {
		if attr.Type.Equal(oid) {
			attr.Values.Bytes = append(attr.Values.Bytes, value...)
			return nil
		}
	}
	*l = append(*l, Attribute{
		Type: oid,
		Values: asn1.RawValue{
			Class:      asn1.ClassUniversal,
			Tag:        asn1.TagSet,
			IsCompound: true,
			Bytes:      value,
		}})
	return nil
}

type SignerInfo struct {
	Version                   int                      `asn1:"default:1"`
	IssuerAndSerialNumber     IssuerAndSerial          ``
	DigestAlgorithm           pkix.AlgorithmIdentifier ``
	AuthenticatedAttributes   AttributeList            `asn1:"optional,tag:0"`
	DigestEncryptionAlgorithm pkix.AlgorithmIdentifier ``
	EncryptedDigest           []byte                   ``
	UnauthenticatedAttributes AttributeList            `asn1:"optional,tag:1"`
}

type IssuerAndSerial struct {
	IssuerName   asn1.RawValue
	SerialNumber *big.Int
}
