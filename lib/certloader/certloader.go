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

package certloader

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"strings"

	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/pkcs7"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/x509tools"
)

const asn1Magic = 0x30 // weak but good enough?
var pkcs7SignedData = []byte{0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02}

// Parse a private key from a blob of PEM or DER data
func ParsePrivateKey(pemData []byte) (crypto.PrivateKey, error) {
	if len(pemData) >= 1 && pemData[0] == asn1Magic {
		// already DER form
		return parsePrivateKey(pemData)
	}
	for {
		var keyBlock *pem.Block
		keyBlock, pemData = pem.Decode(pemData)
		if keyBlock == nil {
			return nil, errors.New("failed to find any private keys in PEM data")
		} else if keyBlock.Type == "PRIVATE KEY" || strings.HasSuffix(keyBlock.Type, " PRIVATE KEY") {
			return parsePrivateKey(keyBlock.Bytes)
		}
	}
}

// Parse a private key from a DER block
// See crypto/tls.parsePrivateKey
func parsePrivateKey(der []byte) (crypto.PrivateKey, error) {
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

// Parse a list of certificates, PEM or DER, X509 or PKCS#7
func ParseCertificates(pemData []byte) ([]*x509.Certificate, error) {
	if len(pemData) >= 1 && pemData[0] == asn1Magic {
		// already in DER form
		return parseCertificates(pemData)
	}
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, pemData = pem.Decode(pemData)
		if block == nil {
			break
		} else if block.Type == "CERTIFICATE" || block.Type == "PKCS7" {
			newcerts, err := parseCertificates(block.Bytes)
			if err != nil {
				return nil, err
			}
			certs = append(certs, newcerts...)
		}
	}
	if len(certs) == 0 {
		return nil, ErrNoCerts
	}
	return certs, nil
}

// Parse certificates from DER
func parseCertificates(der []byte) ([]*x509.Certificate, error) {
	if bytes.Contains(der[:32], pkcs7SignedData) {
		return pkcs7.ParseCertificates(der)
	} else {
		return x509.ParseCertificates(der)
	}
}

// Extends the tls version of this function by parsing p7b files
func LoadX509KeyPair(certFile, keyFile string) (tls.Certificate, error) {
	var tcert tls.Certificate
	keyblob, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return tcert, err
	}
	certblob, err := ioutil.ReadFile(certFile)
	if err != nil {
		return tcert, err
	}
	key, err := ParsePrivateKey(keyblob)
	if err != nil {
		return tcert, err
	}
	tcert.PrivateKey = key
	certs, err := ParseCertificates(certblob)
	if err != nil {
		return tcert, err
	}
	for i, cert := range certs {
		if i == 0 {
			tcert.Leaf = cert
		} else if bytes.Equal(cert.RawSubject, cert.RawIssuer) {
			// omit root CA from the chain
			continue
		}
		tcert.Certificate = append(tcert.Certificate, cert.Raw)
	}
	if tcert.Leaf == nil {
		return tcert, errors.New("No certificates found in chain")
	}
	if !x509tools.SameKey(tcert.Leaf.PublicKey, key) {
		return tcert, errors.New("Private key does not match certificate")
	}
	return tcert, nil
}

type errNoCerts struct{}

func (errNoCerts) Error() string {
	return "failed to find any certificates in PEM file"
}

var ErrNoCerts = errNoCerts{}
