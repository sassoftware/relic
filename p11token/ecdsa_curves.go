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

package p11token

import (
	"crypto/elliptic"
	"encoding/asn1"
	"fmt"
	"strconv"
	"strings"
)

type curveDefinition struct {
	bits  uint
	curve elliptic.Curve
	oid   asn1.ObjectIdentifier
}

var definedCurves []curveDefinition = []curveDefinition{
	{256, elliptic.P256(), asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}},
	{384, elliptic.P384(), asn1.ObjectIdentifier{1, 3, 132, 0, 34}},
	{521, elliptic.P521(), asn1.ObjectIdentifier{1, 3, 132, 0, 35}},
}

func (def *curveDefinition) ToDer() []byte {
	der, err := asn1.Marshal(def.oid)
	if err != nil {
		panic(err)
	}
	return der
}

func supportedCurves() string {
	curves := make([]string, len(definedCurves))
	for i, def := range definedCurves {
		curves[i] = strconv.FormatUint(uint64(def.bits), 10)
	}
	return strings.Join(curves, ", ")
}

func curveByOid(oid asn1.ObjectIdentifier) (*curveDefinition, error) {
	for _, def := range definedCurves {
		if oid.Equal(def.oid) {
			return &def, nil
		}
	}
	return nil, fmt.Errorf("Unsupported ECDSA curve with OID: %s\nSupported curves: %s", oid, supportedCurves())
}

func curveByDer(der []byte) (*curveDefinition, error) {
	var oid asn1.ObjectIdentifier
	_, err := asn1.Unmarshal(der, &oid)
	if err != nil {
		return nil, err
	}
	return curveByOid(oid)
}

func curveByCurve(curve elliptic.Curve) (*curveDefinition, error) {
	for _, def := range definedCurves {
		if curve == def.curve {
			return &def, nil
		}
	}
	return nil, fmt.Errorf("Unsupported ECDSA curve: %v\nSupported curves: %s", curve, supportedCurves())
}

func curveByBits(bits uint) (*curveDefinition, error) {
	for _, def := range definedCurves {
		if bits == def.bits {
			return &def, nil
		}
	}
	return nil, fmt.Errorf("Unsupported ECDSA curve: %v\nSupported curves: %s", bits, supportedCurves())
}
