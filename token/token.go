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

package token

import (
	"crypto"
	"crypto/x509"
	"io"

	"github.com/sassoftware/relic/config"
)

type KeyType uint

const (
	// Values match CKK_RSA etc.
	KeyTypeRsa   KeyType = 0
	KeyTypeEcdsa KeyType = 3
)

type Token interface {
	io.Closer
	// Check that the token is still alive
	Ping() error
	// Return the token config object used to instantiate this token
	Config() *config.TokenConfig
	// Get a key from the token by its config alias
	GetKey(keyName string) (Key, error)
	// Import a public+private keypair into the token
	Import(keyName string, privKey crypto.PrivateKey) (Key, error)
	// Import an issuer certificate into the token. The new object label will
	// be labelBase plus the fingerprint of the certificate.
	ImportCertificate(cert *x509.Certificate, labelBase string) error
	// Generate a new key in the token
	Generate(keyName string, keyType KeyType, bits uint) (Key, error)
}

type Key interface {
	crypto.Signer
	// Return the key config object used to instantiate this key
	Config() *config.KeyConfig
	// Get the CKK_ID or equivalent for the key
	GetID() []byte
	// Import a leaf certificate for this key
	ImportCertificate(cert *x509.Certificate) error
}
