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
	"context"
	"crypto"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/miekg/pkcs11"

	"github.com/sassoftware/relic/v7/config"
	"github.com/sassoftware/relic/v7/signers/sigerrors"
	"github.com/sassoftware/relic/v7/token"
)

type Key struct {
	PgpCertificate  string
	X509Certificate string
	token           *Token
	keyConf         *config.KeyConfig
	keyType         uint
	pub             pkcs11.ObjectHandle
	priv            pkcs11.ObjectHandle
	pubParsed       crypto.PublicKey
}

func (token *Token) GetKey(ctx context.Context, keyName string) (token.Key, error) {
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
		token:           token,
		keyConf:         keyConf,
		PgpCertificate:  keyConf.PgpCertificate,
		X509Certificate: keyConf.X509Certificate,
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
		return nil, errors.New("private key: CKA_KEY_TYPE is missing")
	}
	key.keyType, err = getUlong(keyTypeBlob)
	if err != nil {
		return nil, fmt.Errorf("private key: CKA_KEY_TYPE: %w", err)
	}
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
	if keyConf.ID != "" {
		keyID, err := parseKeyID(keyConf.ID)
		if err != nil {
			return 0, err
		}
		attrs = append(attrs, pkcs11.NewAttribute(pkcs11.CKA_ID, keyID))
	}
	objects, err := token.findObject(attrs)
	if err != nil {
		return 0, err
	} else if len(objects) > 1 {
		return 0, errors.New("Multiple token objects with the specified attributes")
	} else if len(objects) == 0 {
		return 0, sigerrors.KeyNotFoundError{}
	}
	return objects[0], nil
}

func (key *Key) Config() *config.KeyConfig {
	return key.keyConf
}

func (key *Key) Certificate() []byte {
	return nil
}

func (key *Key) Public() crypto.PublicKey {
	return key.pubParsed
}

func (key *Key) getLabel() string {
	key.token.mutex.Lock()
	defer key.token.mutex.Unlock()
	return string(key.token.getAttribute(key.priv, pkcs11.CKA_LABEL))
}

func (key *Key) GetID() []byte {
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

func (key *Key) SignContext(ctx context.Context, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return key.Sign(rand.Reader, digest, opts)
}
