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

type contentInfo2 struct {
	ContentType asn1.ObjectIdentifier
	Value       asn1.RawValue
}

type contentInfoBytes struct {
	ContentType asn1.ObjectIdentifier
	Value       []byte `asn1:"explicit,optional,tag:0"`
}

func NewContentInfo(contentType asn1.ObjectIdentifier, data interface{}) (ci ContentInfo, err error) {
	if data == nil {
		return ContentInfo{ContentType: contentType}, nil
	}
	// There's no way to just encode the struct with the asn1.RawValue directly
	// while also supporting the ability to not emit the 2nd field for the nil
	// case, so instead this stupid dance of encoding it with the field then
	// stuffing it into Raw is necessary...
	encoded, err := asn1.Marshal(data)
	if err != nil {
		return ContentInfo{}, err
	}
	ci2 := contentInfo2{
		ContentType: contentType,
		Value: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      encoded,
		},
	}
	ciblob, err := asn1.Marshal(ci2)
	if err != nil {
		return ContentInfo{}, nil
	}
	return ContentInfo{Raw: ciblob}, nil
}

func (ci ContentInfo) Unmarshal(dest interface{}) (err error) {
	// First re-decode the contentinfo but this time with the second field
	var ci2 contentInfo2
	_, err = asn1.Unmarshal(ci.Raw, &ci2)
	if err == nil {
		// Now decode the raw value in the second field
		_, err = asn1.Unmarshal(ci2.Value.Bytes, dest)
	}
	return
}

func (ci ContentInfo) UnmarshalBytes() ([]byte, error) {
	// Unambigious way to unmarshal bytes if they are there or return nil if
	// they were left out (i.e. detached signature)
	var ci2 contentInfoBytes
	if _, err := asn1.Unmarshal(ci.Raw, &ci2); err != nil {
		return nil, err
	} else {
		return ci2.Value, nil
	}
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
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"set"`
}

type SignerInfo struct {
	Version                   int                      `asn1:"default:1"`
	IssuerAndSerialNumber     IssuerAndSerial          ``
	DigestAlgorithm           pkix.AlgorithmIdentifier ``
	AuthenticatedAttributes   []Attribute              `asn1:"optional,tag:0"`
	DigestEncryptionAlgorithm pkix.AlgorithmIdentifier ``
	EncryptedDigest           []byte                   ``
	UnauthenticatedAttributes []Attribute              `asn1:"optional,tag:1"`
}

type IssuerAndSerial struct {
	IssuerName   asn1.RawValue
	SerialNumber *big.Int
}
