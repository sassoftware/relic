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

package xmldsig

import (
	"crypto"
	"encoding/xml"
)

const (
	NsXMLDsig        = "http://www.w3.org/2000/09/xmldsig#"
	NsXMLDsigMore    = "http://www.w3.org/2001/04/xmldsig-more#"
	NsXMLEnc         = "http://www.w3.org/2001/04/xmlenc#"
	NsXsi            = "http://www.w3.org/2001/XMLSchema-instance"
	AlgXMLExcC14n    = "http://www.w3.org/2001/10/xml-exc-c14n#"
	AlgXMLExcC14nRec = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315" // draft version

	AlgDsigEnvelopedSignature = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
)

// the best thing about namespaces is there are so many to choose from
var nsPrefixes = []string{NsXMLDsig, NsXMLDsigMore, NsXMLEnc}

var hashNames = map[crypto.Hash]string{
	crypto.SHA1:   "sha1",
	crypto.SHA224: "sha224",
	crypto.SHA256: "sha256",
	crypto.SHA384: "sha384",
	crypto.SHA512: "sha512",
}

var HashUris = map[crypto.Hash]string{
	crypto.SHA1:   NsXMLDsig + "sha1",
	crypto.SHA224: NsXMLDsigMore + "sha224",
	crypto.SHA256: NsXMLEnc + "sha256",
	crypto.SHA384: NsXMLDsigMore + "sha384",
	crypto.SHA512: NsXMLEnc + "sha512",
}

type signature struct {
	XMLName xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# Signature"`

	CanonicalizationMethod method    `xml:"SignedInfo>CanonicalizationMethod"`
	SignatureMethod        method    `xml:"SignedInfo>SignatureMethod"`
	Reference              reference `xml:"SignedInfo>Reference"`
	SignatureValue         string    `xml:"SignatureValue"`
	KeyName                string    `xml:"KeyInfo>KeyName,omitempty"`
	KeyValue               *keyValue `xml:"KeyInfo>KeyValue,omitempty"`
	X509Certificates       []string  `xml:"KeyInfo>X509Data>X509Certificate,omitempty"`
}

type reference struct {
	URI          string   `xml:",attr"`
	Transforms   []method `xml:"Transforms>Transform"`
	DigestMethod method
	DigestValue  string
}

type method struct {
	Algorithm string `xml:",attr"`
}

type keyValue struct {
	Modulus    string     `xml:"RSAKeyValue>Modulus,omitempty"`
	Exponent   string     `xml:"RSAKeyValue>Exponent,omitempty"`
	NamedCurve namedCurve `xml:"ECDSAKeyValue>DomainParameters>NamedCurve,omitempty"`
	X          pointValue `xml:"ECDSAKeyValue>PublicKey>X,omitempty"`
	Y          pointValue `xml:"ECDSAKeyValue>PublicKey>Y,omitempty"`
}

type namedCurve struct {
	URN string `xml:",attr"`
}

type pointValue struct {
	Value string `xml:",attr"`
}
