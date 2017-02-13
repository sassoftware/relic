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
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"errors"

	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/pkcs8"
	"github.com/miekg/pkcs11"
)

// Import a PKCS#8 encoded key using a random 3DES key and the Unwrap function.
// For some HSMs this is the only way to import keys.
func (token *Token) importPkcs8(pk8 []byte, attrs []*pkcs11.Attribute) error {
	// Generate a temporary 3DES key
	genMech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_DES3_KEY_GEN, nil)}
	wrapKey, err := token.ctx.GenerateKey(token.sh, genMech, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),
	})
	if err != nil {
		return err
	}
	defer token.ctx.DestroyObject(token.sh, wrapKey)
	// Encrypt key
	iv := make([]byte, 8)
	if _, err := rand.Reader.Read(iv); err != nil {
		return err
	}
	encMech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_DES3_CBC_PAD, iv)}
	if err := token.ctx.EncryptInit(token.sh, encMech, wrapKey); err != nil {
		return err
	}
	wrapped, err := token.ctx.Encrypt(token.sh, pk8)
	if err != nil {
		return err
	}
	// Unwrap key into token
	if _, err := token.ctx.UnwrapKey(token.sh, encMech, wrapKey, wrapped, attrs); err != nil {
		return err
	}
	return nil
}

func (token *Token) Import(keyName string, privKey crypto.PrivateKey) (*Key, error) {
	keyConf, err := token.config.GetKey(keyName)
	if err != nil {
		return nil, err
	}
	if keyConf.Label == "" {
		return nil, errors.New("Key attribute 'label' must be defined in order to create an object")
	}
	keyId := makeKeyId()
	if keyId == nil {
		return nil, errors.New("failed to make key ID")
	}
	var pub_type_specific, priv_type_specific []*pkcs11.Attribute
	var keyType uint
	switch priv := privKey.(type) {
	case *rsa.PrivateKey:
		keyType = pkcs11.CKK_RSA
		pub_type_specific, priv_type_specific, err = rsaImportAttrs(priv)
	case *ecdsa.PrivateKey:
		keyType = pkcs11.CKK_ECDSA
		pub_type_specific, priv_type_specific, err = ecdsaImportAttrs(priv)
	default:
		return nil, errors.New("Unsupported key type")
	}
	if err != nil {
		return nil, err
	}
	shared_attrs := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, keyType),
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyId),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyConf.Label),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
	}
	pub_attrs := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, false),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
	}
	pub_attrs = append(pub_attrs, shared_attrs...)
	priv_attrs := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
	}
	priv_attrs = append(priv_attrs, shared_attrs...)
	pub_attrs = append(pub_attrs, pub_type_specific...)
	pub_handle, err := token.ctx.CreateObject(token.sh, pub_attrs)
	if err != nil {
		return nil, err
	}
	sensitive_priv_attrs := append(priv_attrs, priv_type_specific...)
	_, err = token.ctx.CreateObject(token.sh, sensitive_priv_attrs)
	if err2, ok := err.(pkcs11.Error); ok && err2 == pkcs11.CKR_TEMPLATE_INCONSISTENT {
		// Some HSMs don't seem to allow importing private keys directly so use
		// key wrapping to sneak it in. Exclude the "sensitive" attrs since
		// only the flags, label etc. are useful for Unwrap
		var pk8 []byte
		pk8, err = pkcs8.MarshalPKCS8PrivateKey(privKey)
		if err == nil {
			err = token.importPkcs8(pk8, priv_attrs)
		}
	}
	if err != nil {
		token.ctx.DestroyObject(token.sh, pub_handle)
		return nil, err
	}
	keyConf.Id = hex.EncodeToString(keyId)
	return token.getKey(keyConf, keyName)
}
