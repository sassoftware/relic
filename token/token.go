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
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"io"

	"github.com/sassoftware/relic/v7/config"
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
	Ping(ctx context.Context) error
	// Return the token config object used to instantiate this token
	Config() *config.TokenConfig
	// Get a key from the token by its config alias
	GetKey(ctx context.Context, keyName string) (Key, error)
	// Import a public+private keypair into the token
	Import(keyName string, privKey crypto.PrivateKey) (Key, error)
	// Import an issuer certificate into the token. The new object label will
	// be labelBase plus the fingerprint of the certificate.
	ImportCertificate(cert *x509.Certificate, labelBase string) error
	// Generate a new key in the token
	Generate(keyName string, keyType KeyType, bits uint) (Key, error)
	// Print key info
	ListKeys(opts ListOptions) error
}

type Key interface {
	crypto.Signer
	SignContext(context.Context, []byte, crypto.SignerOpts) ([]byte, error)
	// Return the key config object used to instantiate this key
	Config() *config.KeyConfig
	// Return the X509 certificate chain stored in the token, if any
	Certificate() []byte
	// Get the CKK_ID or equivalent for the key
	GetID() []byte
	// Import a leaf certificate for this key
	ImportCertificate(cert *x509.Certificate) error
}

type ListOptions struct {
	// Destination stream
	Output io.Writer
	// Filter by attributes
	Label string
	ID    string
	// Print key and certificate contents
	Values bool
}

type NotImplementedError struct {
	Op, Type string
}

func (e NotImplementedError) Error() string {
	return fmt.Sprintf("operation %s not implemented for tokens of type %s", e.Op, e.Type)
}

type KeyUsageError struct {
	Key string
	Err error
}

func (e KeyUsageError) Error() string {
	return fmt.Sprintf("key %q: %+v", e.Key, e.Err)
}

func (e KeyUsageError) Unwrap() error {
	return e.Err
}
