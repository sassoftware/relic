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

package xmldsig

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/sassoftware/relic/v7/lib/x509tools"
	"github.com/sassoftware/relic/v7/signers/sigerrors"

	"github.com/beevik/etree"
)

type Signature struct {
	PublicKey       crypto.PublicKey
	Certificates    []*x509.Certificate
	Hash            crypto.Hash
	EncryptedDigest []byte
	Reference       *etree.Element
}

func (s Signature) Leaf() *x509.Certificate {
	for _, cert := range s.Certificates {
		if x509tools.SameKey(cert.PublicKey, s.PublicKey) {
			return cert
		}
	}
	return nil
}

// Extract and verify an enveloped signature at the given root
func Verify(root *etree.Element, sigpath string, extraCerts []*x509.Certificate) (*Signature, error) {
	root = root.Copy()
	sigs := root.FindElements(sigpath)
	if len(sigs) == 0 {
		return nil, sigerrors.NotSignedError{Type: "xmldsig"}
	} else if len(sigs) > 1 {
		return nil, errors.New("xmldsig: multiple signatures found")
	}
	sigEl := sigs[0]
	// parse signature tree
	sigbytes, err := SerializeCanonical(sigEl)
	if err != nil {
		return nil, fmt.Errorf("xmldsig: %w", err)
	}
	var sig signature
	if err := xml.Unmarshal(sigbytes, &sig); err != nil {
		return nil, fmt.Errorf("xmldsig: %w", err)
	}
	// parse algorithms
	if sig.CanonicalizationMethod.Algorithm != AlgXMLExcC14n && sig.CanonicalizationMethod.Algorithm != AlgXMLExcC14nRec {
		return nil, errors.New("xmldsig: unsupported canonicalization method")
	}
	hash, pubtype, err := parseAlgs(sig.Reference.DigestMethod.Algorithm, sig.SignatureMethod.Algorithm)
	if err != nil {
		return nil, err
	}
	// parse public key
	var pubkey crypto.PublicKey
	if sig.KeyValue != nil {
		pubkey, err = parseKey(sig.KeyValue, pubtype)
		if err != nil {
			return nil, err
		}
	}
	// parse x509 certs
	certs := make([]*x509.Certificate, len(extraCerts))
	copy(certs, extraCerts)
	for _, b64 := range sig.X509Certificates {
		der, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return nil, fmt.Errorf("xmldsig: invalid X509 certificate")
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("xmldsig: invalid X509 certificate: %w", err)
		}
		certs = append(certs, cert)
	}
	// check signature
	signedinfo := sigEl.SelectElement("SignedInfo")
	if signedinfo == nil {
		return nil, errors.New("xmldsig: invalid signature")
	}
	siCalc, err := hashCanon(signedinfo, hash)
	if err != nil {
		return nil, err
	}
	sigv, err := base64.StdEncoding.DecodeString(sig.SignatureValue)
	if err != nil {
		return nil, errors.New("xmldsig: invalid signature")
	}
	if pubtype == "ecdsa" {
		// reformat with ASN.1 structure
		sig, err := x509tools.UnpackEcdsaSignature(sigv)
		if err != nil {
			return nil, err
		}
		sigv = sig.Marshal()
	}
	if pubkey == nil {
		// if no KeyValue is present then use the X509 certificate
		if len(certs) == 0 {
			return nil, errors.New("xmldsig: missing public key")
		}
		// no guarantee is made about the order in which certs appear, so try all of them
		for _, cert := range certs {
			err = x509tools.Verify(cert.PublicKey, hash, siCalc, sigv)
			if err == nil {
				pubkey = cert.PublicKey
				break
			}
		}
	} else {
		err = x509tools.Verify(pubkey, hash, siCalc, sigv)
	}
	if err != nil {
		return nil, fmt.Errorf("xmldsig: %w", err)
	}
	// check reference digest
	var reference *etree.Element
	if sig.Reference.URI == "" {
		// enveloped signature
		if len(sig.Reference.Transforms) != 2 ||
			sig.Reference.Transforms[0].Algorithm != AlgDsigEnvelopedSignature ||
			(sig.Reference.Transforms[1].Algorithm != AlgXMLExcC14n && sig.Reference.Transforms[1].Algorithm != AlgXMLExcC14nRec) {
			return nil, errors.New("xmldsig: unsupported reference transform")
		}
		sigEl.Parent().RemoveChild(sigEl)
		reference = root
	} else {
		// enveloping signature
		if len(sig.Reference.Transforms) != 1 ||
			(sig.Reference.Transforms[0].Algorithm != AlgXMLExcC14n && sig.Reference.Transforms[0].Algorithm != AlgXMLExcC14nRec) {
			return nil, errors.New("xmldsig: unsupported reference transform")
		}
		if sig.Reference.URI[0] != '#' {
			return nil, errors.New("xmldsig: unsupported reference URI")
		}
		reference = root.FindElement(fmt.Sprintf("[@Id='%s']", sig.Reference.URI[1:]))
	}
	if reference == nil {
		return nil, errors.New("xmldsig: unable to locate reference")
	}
	refCalc, err := hashCanon(reference, hash)
	if err != nil {
		return nil, err
	}
	refGiven, err := base64.StdEncoding.DecodeString(sig.Reference.DigestValue)
	if len(refGiven) != len(refCalc) || err != nil {
		return nil, errors.New("xmldsig: invalid signature")
	}
	if !hmac.Equal(refGiven, refCalc) {
		return nil, fmt.Errorf("xmldsig: digest mismatch: calculated %x, found %x", refCalc, refGiven)
	}
	return &Signature{
		PublicKey:       pubkey,
		Certificates:    certs,
		Hash:            hash,
		EncryptedDigest: sigv,
		Reference:       reference,
	}, nil
}

func HashAlgorithm(hashAlg string) (string, crypto.Hash) {
	for _, prefix := range nsPrefixes {
		if strings.HasPrefix(hashAlg, prefix) {
			hashAlg = hashAlg[len(prefix):]
			break
		}
	}
	for hash, name := range hashNames {
		if hashAlg == name {
			return hashAlg, hash
		}
	}
	return hashAlg, 0
}

func parseAlgs(hashAlg, sigAlg string) (crypto.Hash, string, error) {
	hashAlg, hash := HashAlgorithm(hashAlg)
	if !hash.Available() {
		return 0, "", errors.New("xmldsig: unsupported digest algorithm")
	}

	for _, prefix := range nsPrefixes {
		if strings.HasPrefix(sigAlg, prefix) {
			sigAlg = sigAlg[len(prefix):]
			break
		}
	}
	if !strings.HasSuffix(sigAlg, "-"+hashAlg) {
		return 0, "", errors.New("xmldsig: unsupported signature algorithm")
	}
	sigAlg = sigAlg[:len(sigAlg)-len(hashAlg)-1]
	if sigAlg != "rsa" && sigAlg != "ecdsa" {
		return 0, "", errors.New("xmldsig: unsupported signature algorithm")
	}
	return hash, sigAlg, nil
}

func parseKey(kv *keyValue, pubtype string) (crypto.PublicKey, error) {
	switch pubtype {
	case "rsa":
		nbytes, err := base64.StdEncoding.DecodeString(kv.Modulus)
		if len(nbytes) == 0 || err != nil {
			return nil, errors.New("xmldsig: invalid public key")
		}
		n := new(big.Int).SetBytes(nbytes)
		ebytes, err := base64.StdEncoding.DecodeString(kv.Exponent)
		if len(ebytes) == 0 || err != nil {
			return nil, errors.New("xmldsig: invalid public key")
		}
		ebig := new(big.Int).SetBytes(ebytes)
		if ebig.BitLen() > 30 {
			return nil, errors.New("xmldsig: invalid public key")
		}
		e := int(ebig.Int64())
		return &rsa.PublicKey{N: n, E: e}, nil
	case "ecdsa":
		if !strings.HasPrefix(kv.NamedCurve.URN, "urn:oid:") {
			return nil, errors.New("xmldsig: unsupported ECDSA curve")
		}
		curve, err := x509tools.CurveByOidString(kv.NamedCurve.URN[8:])
		if err != nil {
			return nil, fmt.Errorf("xmldsig: %w", err)
		}
		x, ok := new(big.Int).SetString(kv.X.Value, 10)
		if !ok {
			return nil, errors.New("xmldsig: invalid public key")
		}
		y, ok := new(big.Int).SetString(kv.Y.Value, 10)
		if !ok {
			return nil, errors.New("xmldsig: invalid public key")
		}
		if !curve.Curve.IsOnCurve(x, y) {
			return nil, errors.New("xmldsig: invalid public key")
		}
		return &ecdsa.PublicKey{Curve: curve.Curve, X: x, Y: y}, nil
	default:
		return nil, errors.New("xmldsig: unsupported signature algorithm")
	}
}
