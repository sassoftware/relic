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
	OidSpcSpOpusInfo          = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 12}
	OidSpcPeImageData         = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 15}
)

type SpcIndirectDataContent struct {
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
	// not implemented
	Raw asn1.RawValue
}

type SpcSpOpusInfo struct {
	// TODO
}
