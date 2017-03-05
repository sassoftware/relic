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
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf16"
)

type rdnAttr struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue
}

type rdnNameSet []rdnAttr

type NameStyle int

const (
	NameStyleLdap NameStyle = iota
	NameStyleMsOsco
)

type attrName struct {
	Type asn1.ObjectIdentifier
	Name string
}

var nameStyleLdap = []attrName{
	attrName{asn1.ObjectIdentifier{2, 5, 4, 3}, "CN"},
	attrName{asn1.ObjectIdentifier{2, 5, 4, 4}, "surname"},
	attrName{asn1.ObjectIdentifier{2, 5, 4, 5}, "serialNumber"},
	attrName{asn1.ObjectIdentifier{2, 5, 4, 6}, "C"},
	attrName{asn1.ObjectIdentifier{2, 5, 4, 7}, "L"},
	attrName{asn1.ObjectIdentifier{2, 5, 4, 8}, "ST"},
	attrName{asn1.ObjectIdentifier{2, 5, 4, 9}, "street"},
	attrName{asn1.ObjectIdentifier{2, 5, 4, 10}, "O"},
	attrName{asn1.ObjectIdentifier{2, 5, 4, 11}, "OU"},
	attrName{asn1.ObjectIdentifier{2, 5, 4, 12}, "title"},
	attrName{asn1.ObjectIdentifier{2, 5, 4, 13}, "description"},
	attrName{asn1.ObjectIdentifier{2, 5, 4, 17}, "postalCode"},
	attrName{asn1.ObjectIdentifier{2, 5, 4, 18}, "postOfficeBox"},
	attrName{asn1.ObjectIdentifier{2, 5, 4, 20}, "telephoneNumber"},
	attrName{asn1.ObjectIdentifier{2, 5, 4, 42}, "givenName"},
	attrName{asn1.ObjectIdentifier{2, 5, 4, 43}, "initials"},
	attrName{asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}, "dc"},
	attrName{asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}, "emailAddress"},
}

// Per [MS-OSCO]
// https://msdn.microsoft.com/en-us/library/dd947276(v=office.12).aspx
var nameStyleMsOsco = []attrName{
	attrName{asn1.ObjectIdentifier{2, 5, 4, 3}, "CN"},
	attrName{asn1.ObjectIdentifier{2, 5, 4, 7}, "L"},
	attrName{asn1.ObjectIdentifier{2, 5, 4, 10}, "O"},
	attrName{asn1.ObjectIdentifier{2, 5, 4, 11}, "OU"},
	attrName{asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}, "E"},
	attrName{asn1.ObjectIdentifier{2, 5, 4, 6}, "C"},
	attrName{asn1.ObjectIdentifier{2, 5, 4, 8}, "S"},
	attrName{asn1.ObjectIdentifier{2, 5, 4, 9}, "STREET"},
	attrName{asn1.ObjectIdentifier{2, 5, 4, 12}, "T"},
	attrName{asn1.ObjectIdentifier{2, 5, 4, 42}, "G"},
	attrName{asn1.ObjectIdentifier{2, 5, 4, 43}, "I"},
	attrName{asn1.ObjectIdentifier{2, 5, 4, 4}, "SN"},
	attrName{asn1.ObjectIdentifier{2, 5, 4, 5}, "SERIALNUMBER"},
	attrName{asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}, "DC"},
	attrName{asn1.ObjectIdentifier{2, 5, 4, 13}, "Description"},
	attrName{asn1.ObjectIdentifier{2, 5, 4, 17}, "PostalCode"},
	attrName{asn1.ObjectIdentifier{2, 5, 4, 18}, "POBox"},
	attrName{asn1.ObjectIdentifier{2, 5, 4, 20}, "Phone"},
}

const InvalidName = "<invalid>"

func FormatPkixName(der []byte, style NameStyle) string {
	var seq asn1.RawValue
	if _, err := asn1.Unmarshal(der, &seq); err != nil {
		return InvalidName
	}
	multi := false
	if style == NameStyleLdap {
		multi = true
	}
	seqbytes := seq.Bytes
	var formatted []string
	for len(seqbytes) > 0 {
		var rdnSet rdnNameSet
		var err error
		seqbytes, err = asn1.UnmarshalWithParams(seqbytes, &rdnSet, "set")
		if err != nil {
			return InvalidName
		}
		var elems []string
		for _, attr := range rdnSet {
			elems = append(elems, fmt.Sprintf("%s=%s", attName(attr.Type, style), attValue(attr.Value, style)))
		}
		if multi {
			rdnf := strings.Join(elems, "+")
			formatted = append(formatted, rdnf)
		} else {
			formatted = append(formatted, elems...)
		}
	}
	if len(formatted) == 0 {
		return ""
	}
	switch style {
	case NameStyleLdap:
		return "/" + strings.Join(formatted, "/") + "/"
	case NameStyleMsOsco:
		return strings.Join(formatted, ", ")
	default:
		panic("invalid style argument")
	}
}

func attName(t asn1.ObjectIdentifier, style NameStyle) string {
	var names []attrName
	var defaultPrefix string
	switch style {
	case NameStyleLdap:
		names = nameStyleLdap
	case NameStyleMsOsco:
		names = nameStyleMsOsco
		defaultPrefix = "OID."
	default:
		panic("invalid style argument")
	}
	for _, name := range names {
		if name.Type.Equal(t) {
			return name.Name
		}
	}
	return defaultPrefix + t.String()
}

func attValue(raw asn1.RawValue, style NameStyle) string {
	var value string
	switch raw.Tag {
	case asn1.TagUTF8String, asn1.TagIA5String, asn1.TagPrintableString:
		var ret interface{}
		if _, err := asn1.Unmarshal(raw.FullBytes, &ret); err != nil {
			return InvalidName
		}
		value = ret.(string)
	case 30: // BMPString
		words := make([]uint16, len(raw.Bytes)/2)
		if err := binary.Read(bytes.NewReader(raw.Bytes), binary.BigEndian, words); err != nil {
			return InvalidName
		}
		value = string(utf16.Decode(words))
	default:
		return InvalidName
	}
	switch style {
	case NameStyleLdap:
		value = strings.Replace(value, "/", "\\/", -1)
	case NameStyleMsOsco:
		quote := false
		if len(value) == 0 {
			quote = true
		}
		if strings.HasPrefix(value, " ") || strings.HasSuffix(value, " ") {
			quote = true
		}
		if i := strings.IndexAny(value, ",+=\n<>#;'\""); i >= 0 {
			quote = true
		}
		value = strings.Replace(value, "\"", "\"\"", -1)
		if quote {
			value = "\"" + value + "\""
		}
	}
	return value
}

func FormatSubject(cert *x509.Certificate) string {
	return FormatPkixName(cert.RawSubject, NameStyleLdap)
}

func FormatIssuer(cert *x509.Certificate) string {
	return FormatPkixName(cert.RawIssuer, NameStyleLdap)
}
