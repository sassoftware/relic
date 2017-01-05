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
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/fullsailor/pkcs7"
)

// Parse a private key from a blob of PEM data
func ParsePEMPrivateKey(pemData []byte) (crypto.PrivateKey, error) {
	var keyBlock *pem.Block
	for {
		keyBlock, pemData = pem.Decode(pemData)
		if keyBlock == nil {
			return nil, errors.New("failed to find any private keys in PEM data")
		}
		if keyBlock.Type == "PRIVATE KEY" || strings.HasSuffix(keyBlock.Type, " PRIVATE KEY") {
			return ParsePrivateKey(keyBlock.Bytes)
		}
	}
}

// Parse a private key from a DER block
// See crypto/tls.parsePrivateKey
func ParsePrivateKey(der []byte) (crypto.PrivateKey, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey:
			return key, nil
		default:
			return nil, errors.New("tls: found unknown private key type in PKCS#8 wrapping")
		}
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}

	return nil, errors.New("tls: failed to parse private key")
}

// Extends the tls version of this function by parsing p7b files
func LoadX509KeyPair(certFile, keyFile string) (tls.Certificate, error) {
	if !strings.HasSuffix(certFile, ".p7b") {
		return tls.LoadX509KeyPair(certFile, keyFile)
	}
	var tcert tls.Certificate
	keyblob, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return tcert, err
	}
	certblob, err := ioutil.ReadFile(certFile)
	if err != nil {
		return tcert, err
	}
	key, err := ParsePEMPrivateKey(keyblob)
	if err != nil {
		return tcert, err
	}
	tcert.PrivateKey = key
	if bytes.Equal(certblob[:5], []byte("-----")) {
		pemdata := certblob
		found := false
		for {
			var block *pem.Block
			block, pemdata = pem.Decode(pemdata)
			if block == nil {
				break
			} else if block.Type == "CERTIFICATE" {
				found = true
				certblob = block.Bytes
				break
			}
		}
		if !found {
			return tcert, fmt.Errorf("No certificate block found in %s", certFile)
		}
	}
	p7b, err := pkcs7.Parse(certblob)
	if err != nil {
		return tcert, fmt.Errorf("Unable to parse p7b certificate chain: %s", err)
	}
	for i, cert := range p7b.Certificates {
		if i == 0 {
			tcert.Leaf = cert
		} else if bytes.Equal(cert.RawSubject, cert.RawIssuer) {
			// omit root CA from the chain
			continue
		}
		tcert.Certificate = append(tcert.Certificate, cert.Raw)
	}
	if tcert.Leaf == nil {
		return tcert, errors.New("No certificates found in PKCS#7 chain")
	}
	if !SameKey(tcert.Leaf.PublicKey, key) {
		return tcert, errors.New("Private key does not match certificate")
	}
	return tcert, nil
}
