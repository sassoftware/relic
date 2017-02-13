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
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"fmt"
	"math/big"
	"strconv"
	"strings"
)

type CurveDefinition struct {
	Bits  uint
	Curve elliptic.Curve
	Oid   asn1.ObjectIdentifier
}

var DefinedCurves []CurveDefinition = []CurveDefinition{
	{256, elliptic.P256(), asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}},
	{384, elliptic.P384(), asn1.ObjectIdentifier{1, 3, 132, 0, 34}},
	{521, elliptic.P521(), asn1.ObjectIdentifier{1, 3, 132, 0, 35}},
}

func (def *CurveDefinition) ToDer() []byte {
	der, err := asn1.Marshal(def.Oid)
	if err != nil {
		panic(err)
	}
	return der
}

func SupportedCurves() string {
	curves := make([]string, len(DefinedCurves))
	for i, def := range DefinedCurves {
		curves[i] = strconv.FormatUint(uint64(def.Bits), 10)
	}
	return strings.Join(curves, ", ")
}

func CurveByOid(oid asn1.ObjectIdentifier) (*CurveDefinition, error) {
	for _, def := range DefinedCurves {
		if oid.Equal(def.Oid) {
			return &def, nil
		}
	}
	return nil, fmt.Errorf("Unsupported ECDSA curve with OID: %s\nSupported curves: %s", oid, SupportedCurves())
}

func CurveByDer(der []byte) (*CurveDefinition, error) {
	var oid asn1.ObjectIdentifier
	_, err := asn1.Unmarshal(der, &oid)
	if err != nil {
		return nil, err
	}
	return CurveByOid(oid)
}

func CurveByCurve(curve elliptic.Curve) (*CurveDefinition, error) {
	for _, def := range DefinedCurves {
		if curve == def.Curve {
			return &def, nil
		}
	}
	return nil, fmt.Errorf("Unsupported ECDSA curve: %v\nSupported curves: %s", curve, SupportedCurves())
}

func CurveByBits(bits uint) (*CurveDefinition, error) {
	for _, def := range DefinedCurves {
		if bits == def.Bits {
			return &def, nil
		}
	}
	return nil, fmt.Errorf("Unsupported ECDSA curve: %v\nSupported curves: %s", bits, SupportedCurves())
}

func DerToPoint(curve elliptic.Curve, der []byte) (*big.Int, *big.Int) {
	var blob []byte
	switch der[0] {
	case asn1.TagOctetString:
		_, err := asn1.Unmarshal(der, &blob)
		if err != nil {
			return nil, nil
		}
	case asn1.TagBitString:
		var bits asn1.BitString
		_, err := asn1.Unmarshal(der, &bits)
		if err != nil {
			return nil, nil
		}
		blob = bits.Bytes
	default:
		return nil, nil
	}
	return elliptic.Unmarshal(curve, blob)
}

func PointToDer(pub *ecdsa.PublicKey) []byte {
	blob := elliptic.Marshal(pub.Curve, pub.X, pub.Y)
	der, err := asn1.Marshal(blob)
	if err != nil {
		return nil
	}
	return der
}
