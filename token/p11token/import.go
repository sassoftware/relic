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

package p11token

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/miekg/pkcs11"

	"github.com/sassoftware/relic/v7/token"
)

// Common attributes for new public keys
var newPublicKeyAttrs = []*pkcs11.Attribute{
	pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
	pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
	pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, false),
	pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
}

// Common attributes for new private keys
var newPrivateKeyAttrs = []*pkcs11.Attribute{
	pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
	pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
	pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
	pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
	pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
	pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
}

// Import a PKCS#8 encoded key using a random 3DES key and the Unwrap function.
// For some HSMs this is the only way to import keys.
func (tok *Token) importPkcs8(pk8 []byte, attrs []*pkcs11.Attribute) (err error) {
	// Generate a temporary 3DES key
	genMech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_DES3_KEY_GEN, nil)}
	wrapKey, err := tok.ctx.GenerateKey(tok.sh, genMech, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),
	})
	if err != nil {
		return err
	}
	defer func() {
		err2 := tok.ctx.DestroyObject(tok.sh, wrapKey)
		if err2 != nil && err == nil {
			err = fmt.Errorf("destroying temporary key: %w", err2)
		}
	}()
	// Encrypt key
	iv := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return err
	}
	encMech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_DES3_CBC_PAD, iv)}
	if err := tok.ctx.EncryptInit(tok.sh, encMech, wrapKey); err != nil {
		return err
	}
	wrapped, err := tok.ctx.Encrypt(tok.sh, pk8)
	if err != nil {
		return err
	}
	// Unwrap key into token
	if _, err := tok.ctx.UnwrapKey(tok.sh, encMech, wrapKey, wrapped, attrs); err != nil {
		return err
	}
	return nil
}

// Import an RSA or ECDSA private key into the token
func (tok *Token) Import(keyName string, privKey crypto.PrivateKey) (token.Key, error) {
	keyConf, err := tok.config.GetKey(keyName)
	if err != nil {
		return nil, err
	}
	if keyConf.Label == "" {
		return nil, errors.New("Key attribute 'label' must be defined in order to create an object")
	}
	keyID := makeKeyID()
	if keyID == nil {
		return nil, errors.New("failed to make key ID")
	}
	var pubTypeAttrs, privTypeAttrs []*pkcs11.Attribute
	var keyType uint
	switch priv := privKey.(type) {
	case *rsa.PrivateKey:
		keyType = pkcs11.CKK_RSA
		pubTypeAttrs, privTypeAttrs, err = rsaImportAttrs(priv)
	case *ecdsa.PrivateKey:
		keyType = pkcs11.CKK_ECDSA
		pubTypeAttrs, privTypeAttrs, err = ecdsaImportAttrs(priv)
	default:
		return nil, errors.New("Unsupported key type")
	}
	if err != nil {
		return nil, err
	}
	commonAttrs := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, keyType),
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyConf.Label),
	}
	pubAttrs := attrConcat(commonAttrs, newPublicKeyAttrs, pubTypeAttrs)
	privAttrsSensitive := attrConcat(commonAttrs, newPrivateKeyAttrs, privTypeAttrs)
	pubHandle, err := tok.ctx.CreateObject(tok.sh, pubAttrs)
	if err != nil {
		return nil, err
	}
	_, err = tok.ctx.CreateObject(tok.sh, privAttrsSensitive)
	if err2, ok := err.(pkcs11.Error); ok && err2 == pkcs11.CKR_TEMPLATE_INCONSISTENT {
		// Some HSMs don't seem to allow importing private keys directly so use
		// key wrapping to sneak it in. Exclude the "sensitive" attrs since
		// only the flags, label etc. are useful for Unwrap
		privAttrsUnwrap := attrConcat(commonAttrs, newPrivateKeyAttrs)
		var pk8 []byte
		pk8, err = x509.MarshalPKCS8PrivateKey(privKey)
		if err == nil {
			err = tok.importPkcs8(pk8, privAttrsUnwrap)
		}
	}
	if err != nil {
		_ = tok.ctx.DestroyObject(tok.sh, pubHandle)
		return nil, err
	}
	keyConf.ID = hex.EncodeToString(keyID)
	return tok.getKey(keyConf, keyName)
}

// Generate an RSA or ECDSA key in the token
func (tok *Token) Generate(keyName string, keyType token.KeyType, bits uint) (token.Key, error) {
	tok.mutex.Lock()
	defer tok.mutex.Unlock()
	keyConf, err := tok.config.GetKey(keyName)
	if err != nil {
		return nil, err
	}
	if keyConf.Label == "" {
		return nil, errors.New("Key attribute 'label' must be defined in order to create an object")
	}
	keyID := makeKeyID()
	if keyID == nil {
		return nil, errors.New("failed to make key ID")
	}
	var pubTypeAttrs []*pkcs11.Attribute
	var mech *pkcs11.Mechanism
	switch keyType {
	case token.KeyTypeRsa:
		pubTypeAttrs, mech, err = rsaGenerateAttrs(bits)
	case token.KeyTypeEcdsa:
		pubTypeAttrs, mech, err = ecdsaGenerateAttrs(bits)
	default:
		return nil, errors.New("Unsupported key type")
	}
	if err != nil {
		return nil, err
	}
	commonAttrs := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyConf.Label),
	}
	pubAttrs := attrConcat(commonAttrs, newPublicKeyAttrs, pubTypeAttrs)
	privAttrs := attrConcat(commonAttrs, newPrivateKeyAttrs)
	if _, _, err := tok.ctx.GenerateKeyPair(tok.sh, []*pkcs11.Mechanism{mech}, pubAttrs, privAttrs); err != nil {
		if err2, ok := err.(pkcs11.Error); ok && err2 == pkcs11.CKR_MECHANISM_INVALID && mech.Mechanism == pkcs11.CKM_RSA_X9_31_KEY_PAIR_GEN {
			mech.Mechanism = pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN
			if _, _, err := tok.ctx.GenerateKeyPair(tok.sh, []*pkcs11.Mechanism{mech}, pubAttrs, privAttrs); err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}
	keyConf.ID = hex.EncodeToString(keyID)
	return tok.getKey(keyConf, keyName)
}

func attrConcat(attrSets ...[]*pkcs11.Attribute) []*pkcs11.Attribute {
	ret := make([]*pkcs11.Attribute, 0)
	for _, attrs := range attrSets {
		ret = append(ret, attrs...)
	}
	return ret
}
