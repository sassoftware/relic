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
	"encoding/hex"
	"errors"
	"io"

	"gerrit-pdt.unx.sas.com/tools/relic.git/config"
	"github.com/miekg/pkcs11"
)

type Key struct {
	Name        string
	Certificate string
	token       *Token
	keyType     uint
	pub         pkcs11.ObjectHandle
	priv        pkcs11.ObjectHandle
	pubParsed   crypto.PublicKey
}

func (token *Token) GetKey(keyName string) (*Key, error) {
	token.mutex.Lock()
	defer token.mutex.Unlock()
	keyConf, err := token.config.GetKey(keyName)
	if err != nil {
		return nil, err
	}
	return token.getKey(keyConf, keyName)
}

func (token *Token) getKey(keyConf *config.KeyConfig, keyName string) (*Key, error) {
	var err error
	key := &Key{
		Name:        keyName,
		token:       token,
		Certificate: keyConf.Certificate,
	}
	key.priv, err = token.findKey(keyConf, pkcs11.CKO_PRIVATE_KEY)
	if err != nil {
		return nil, err
	}
	key.pub, err = token.findKey(keyConf, pkcs11.CKO_PUBLIC_KEY)
	if err != nil {
		return nil, err
	}
	keyTypeBlob := token.getAttribute(key.priv, pkcs11.CKA_KEY_TYPE)
	if len(keyTypeBlob) == 0 {
		return nil, errors.New("Missing CKA_KEY_TYPE on private key")
	}
	key.keyType = attrToInt(keyTypeBlob)
	switch key.keyType {
	case CKK_RSA:
		key.pubParsed, err = key.toRsaKey()
	case CKK_ECDSA:
		key.pubParsed, err = key.toEcdsaKey()
	default:
		return nil, errors.New("Unsupported key type")
	}
	if err != nil {
		return nil, err
	}
	return key, nil
}

func (token *Token) findKey(keyConf *config.KeyConfig, class uint) (pkcs11.ObjectHandle, error) {
	attrs := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, class),
	}
	if keyConf.Label != "" {
		attrs = append(attrs, pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyConf.Label))
	}
	if keyConf.Id != "" {
		keyId, err := parseKeyId(keyConf.Id)
		if err != nil {
			return 0, err
		}
		attrs = append(attrs, pkcs11.NewAttribute(pkcs11.CKA_ID, keyId))
	}
	err := token.ctx.FindObjectsInit(token.sh, attrs)
	if err != nil {
		return 0, err
	}
	objects, _, err := token.ctx.FindObjects(token.sh, 2)
	if err != nil {
		return 0, err
	}
	err = token.ctx.FindObjectsFinal(token.sh)
	if err != nil {
		return 0, err
	}
	if len(objects) > 1 {
		return 0, errors.New("Multiple token objects with the specified attributes")
	} else if len(objects) == 0 {
		return 0, KeyNotFoundError{}
	}
	return objects[0], nil
}

func (key *Key) Public() crypto.PublicKey {
	return key.pubParsed
}

func (key *Key) GetId() []byte {
	key.token.mutex.Lock()
	defer key.token.mutex.Unlock()
	return key.token.getAttribute(key.priv, pkcs11.CKA_ID)
}

func (key *Key) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	key.token.mutex.Lock()
	defer key.token.mutex.Unlock()
	switch key.keyType {
	case CKK_RSA:
		return key.signRSA(digest, opts)
	case CKK_ECDSA:
		return key.signECDSA(digest)
	default:
		return nil, errors.New("Unsupported key type")
	}
}

func (token *Token) Generate(keyName string, keyType uint, bits uint) (*Key, error) {
	token.mutex.Lock()
	defer token.mutex.Unlock()
	keyConf, err := token.config.GetKey(keyName)
	if err != nil {
		return nil, err
	}
	if keyConf.Label == "" {
		return nil, errors.New("Key attribute 'label' must be defined in order to create an object")
	}
	var keyId []byte
	switch keyType {
	case CKK_RSA:
		keyId, err = token.generateRSA(keyConf.Label, bits)
	case CKK_ECDSA:
		keyId, err = token.generateECDSA(keyConf.Label, bits)
	default:
		return nil, errors.New("Unsupported key type")
	}
	if err != nil {
		return nil, err
	}
	keyConf.Id = hex.EncodeToString(keyId)
	return token.getKey(keyConf, keyName)
}
