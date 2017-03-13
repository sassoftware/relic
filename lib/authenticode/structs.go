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

package authenticode

import (
	"crypto/x509/pkix"
	"encoding/asn1"
)

var (
	OidSpcIndirectDataContent = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 4}
	OidSpcStatementType       = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 11}
	OidSpcSpOpusInfo          = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 12}
	OidSpcPeImageData         = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 15}
	OidSpcCabImageData        = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 25}
	OidSpcSipInfo             = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 30}
	OidSpcPageHashV1          = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 3, 1}
	OidSpcPageHashV2          = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 3, 2}
	OidSpcCabPageHash         = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 5, 1}
	OidCertTrustList          = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 1}

	SpcUuidPageHashes = []byte{0xa6, 0xb5, 0x86, 0xd5, 0xb4, 0xa1, 0x24, 0x66, 0xae, 0x05, 0xa2, 0x17, 0xda, 0x8e, 0x60, 0xd6}

	// SIP or Subject Interface Package is an internal Microsoft API for
	// transforming arbitrary files into a digestible stream. These ClassIDs
	// are found in the indirect data section and identify the type of processor needed to validate the signature.
	// SIP related DLLs are registered at
	// HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllCreateIndirectData
	// although these particular ClassIDs do not seem to appear there.
	// Relevant DLLs include: WINTRUST.DLL, MSISIP.DLL, pwrshsip.dll
	SpcUuidSipInfoMsi = []byte{0xf1, 0x10, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}
	SpcUuidSipInfoPs  = []byte{0x1f, 0xcc, 0x3b, 0x60, 0x59, 0x4b, 0x08, 0x4e, 0xb7, 0x24, 0xd2, 0xc6, 0x29, 0x7e, 0xf3, 0x51}

	// Filenames for MSI streams holding signature data
	msiDigitalSignature   = "\x05DigitalSignature"
	msiDigitalSignatureEx = "\x05MsiDigitalSignatureEx"
)

type SpcIndirectDataContentPe struct {
	Data          SpcAttributePeImageData
	MessageDigest DigestInfo
}

type SpcAttributePeImageData struct {
	Type  asn1.ObjectIdentifier
	Value SpcPeImageData `asn1:"optional"`
}

type DigestInfo struct {
	DigestAlgorithm pkix.AlgorithmIdentifier
	Digest          []byte
}

type SpcPeImageData struct {
	Flags asn1.BitString
	File  SpcLink `asn1:"tag:0"`
}

type SpcLink struct {
	Url     string              `asn1:"optional,tag:0,ia5"`
	Moniker SpcSerializedObject `asn1:"optional,tag:1"`
	File    SpcString           `asn1:"optional,tag:2"`
}

type SpcString struct {
	Unicode string `asn1:"optional,tag:0,utf8"`
	Ascii   string `asn1:"optional,tag:1,ia5"`
}

type SpcSerializedObject struct {
	ClassId        []byte
	SerializedData []byte
}

type SpcAttributePageHashes struct {
	Type   asn1.ObjectIdentifier
	Hashes [][]byte `asn1:"set"`
}

type SpcSpOpusInfo struct {
	// TODO
}

type SpcIndirectDataContentMsi struct {
	Data          SpcAttributeMsiImageData
	MessageDigest DigestInfo
}

type SpcAttributeMsiImageData struct {
	Type  asn1.ObjectIdentifier
	Value SpcSipInfo `asn1:"optional"`
}

type SpcSipInfo struct {
	A             int
	Uuid          []byte
	B, C, D, E, F int
}

var defaultSipInfo = SpcSipInfo{1, SpcUuidSipInfoMsi, 0, 0, 0, 0, 0}
var psSipInfo = SpcSipInfo{65536, SpcUuidSipInfoPs, 0, 0, 0, 0, 0}

//type CertTrustList struct {
//	SubjectUsage     []asn1.ObjectIdentifier
//	ListIdentifier   []byte
//	EffectiveDate    time.Time
//	SubjectAlgorithm pkix.AlgorithmIdentifier
//	Entries          []CertTrustEntry
//}
