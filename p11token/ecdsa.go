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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"errors"
	"math/big"

	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/x509tools"
	"github.com/miekg/pkcs11"
)

func derToPoint(curve elliptic.Curve, der []byte) (*big.Int, *big.Int) {
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

func pointToDer(pub *ecdsa.PublicKey) []byte {
	blob := elliptic.Marshal(pub.Curve, pub.X, pub.Y)
	der, err := asn1.Marshal(blob)
	if err != nil {
		return nil
	}
	return der
}

func (key *Key) toEcdsaKey() (crypto.PublicKey, error) {
	ecparams := key.token.getAttribute(key.pub, pkcs11.CKA_EC_PARAMS)
	ecpoint := key.token.getAttribute(key.pub, pkcs11.CKA_EC_POINT)
	if len(ecparams) == 0 || len(ecpoint) == 0 {
		return nil, errors.New("Unable to retrieve ECDSA public key")
	}
	curve, err := x509tools.CurveByDer(ecparams)
	if err != nil {
		return nil, err
	}
	x, y := derToPoint(curve.Curve, ecpoint)
	if x == nil || y == nil {
		return nil, errors.New("Invalid elliptic curve point")
	}
	eckey := &ecdsa.PublicKey{Curve: curve.Curve, X: x, Y: y}
	return eckey, nil
}

type ecdsaSignature struct {
	R, S *big.Int
}

func (key *Key) signECDSA(digest []byte) (der []byte, err error) {
	mech := pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)
	err = key.token.ctx.SignInit(key.token.sh, []*pkcs11.Mechanism{mech}, key.priv)
	if err != nil {
		return nil, err
	}
	sig, err := key.token.ctx.Sign(key.token.sh, digest)
	if err != nil {
		return nil, err
	}
	sigBytes := len(sig) / 2
	r := bytesToBig(sig[:sigBytes])
	s := bytesToBig(sig[sigBytes:])
	return asn1.Marshal(ecdsaSignature{r, s})
}

func (token *Token) importECDSA(label string, priv *ecdsa.PrivateKey) ([]byte, error) {
	keyId := makeKeyId()
	if keyId == nil {
		return nil, errors.New("failed to make key ID")
	}
	curve, err := x509tools.CurveByCurve(priv.Curve)
	if err != nil {
		return nil, err
	}
	shared_attrs := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyId),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, CKK_ECDSA),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, curve.ToDer()),
	}
	pub_attrs := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, false),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, pointToDer(&priv.PublicKey)),
	}
	pub_attrs = append(pub_attrs, shared_attrs...)
	priv_attrs := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, priv.D.Bytes()),
	}
	priv_attrs = append(priv_attrs, shared_attrs...)
	priv_handle, err := token.ctx.CreateObject(token.sh, priv_attrs)
	if err != nil {
		return nil, err
	}
	_, err = token.ctx.CreateObject(token.sh, pub_attrs)
	if err != nil {
		token.ctx.DestroyObject(token.sh, priv_handle)
		return nil, err
	}
	return keyId, nil
}

func (token *Token) generateECDSA(label string, bits uint) (keyId []byte, err error) {
	curve, err := x509tools.CurveByBits(bits)
	if err != nil {
		return nil, err
	}
	keyId = makeKeyId()
	if keyId == nil {
		return nil, errors.New("failed to make key ID")
	}
	shared_attrs := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyId),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
	}
	pub_attrs := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, curve.ToDer()),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, false),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
	}
	pub_attrs = append(pub_attrs, shared_attrs...)
	priv_attrs := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
	}
	priv_attrs = append(priv_attrs, shared_attrs...)
	mech := pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil)
	_, _, err = token.ctx.GenerateKeyPair(token.sh, []*pkcs11.Mechanism{mech}, pub_attrs, priv_attrs)
	if err != nil {
		return nil, err
	}
	return keyId, nil
}
