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

	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/x509tools"

	"github.com/beevik/etree"
)

type Signature struct {
	PublicKey       crypto.PublicKey
	Certificates    []*x509.Certificate
	Hash            crypto.Hash
	EncryptedDigest []byte
}

// Extract and verify an enveloped signature at the given root
func Verify(root *etree.Element, sigpath string) (*Signature, error) {
	root = root.Copy()
	sigs := root.FindElements(sigpath)
	if len(sigs) == 0 {
		return nil, errors.New("xmldsig: signature not found")
	} else if len(sigs) > 1 {
		return nil, errors.New("xmldsig: multiple signatures found")
	}
	sigEl := sigs[0]
	// parse signature tree
	sigbytes, err := SerializeCanonical(sigEl)
	if err != nil {
		return nil, fmt.Errorf("xmldsig: %s", err)
	}
	var sig signature
	if err := xml.Unmarshal(sigbytes, &sig); err != nil {
		return nil, fmt.Errorf("xmldsig: %s", err)
	}
	// parse algorithms
	if sig.CanonicalizationMethod.Algorithm != AlgXMLExcC14n {
		return nil, errors.New("xmldsig: unsupported canonicalization method")
	}
	if len(sig.ReferenceTransforms) != 2 ||
		sig.ReferenceTransforms[0].Algorithm != AlgDsigEnvelopedSignature ||
		sig.ReferenceTransforms[1].Algorithm != AlgXMLExcC14n {
		return nil, errors.New("xmldsig: unsupported reference transform")
	}
	hash, pubtype, err := parseAlgs(sig.DigestMethod.Algorithm, sig.SignatureMethod.Algorithm)
	if err != nil {
		return nil, err
	}
	// check signature
	pubkey, err := parseKey(sig.KeyValue, pubtype)
	if err != nil {
		return nil, err
	}
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
	if err := x509tools.Verify(pubkey, hash, siCalc, sigv); err != nil {
		return nil, fmt.Errorf("xmldsig: %s", err)
	}
	// check reference digest
	sigEl.Parent().RemoveChild(sigEl)
	refCalc, err := hashCanon(root, hash)
	if err != nil {
		return nil, err
	}
	refGiven, err := base64.StdEncoding.DecodeString(sig.DigestValue)
	if len(refGiven) != len(refCalc) || err != nil {
		return nil, errors.New("xmldsig: invalid signature")
	}
	if !hmac.Equal(refGiven, refCalc) {
		return nil, fmt.Errorf("xmldsig: digest mismatch: calculated %x, found %x", refCalc, refGiven)
	}
	// parse x509 certs if present
	var certs []*x509.Certificate
	for _, b64 := range sig.X509Certificates {
		der, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return nil, fmt.Errorf("xmldsig: invalid X509 certificate")
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("xmldsig: invalid X509 certificate: %s", err)
		}
		certs = append(certs, cert)
	}
	return &Signature{pubkey, certs, hash, sigv}, nil
}

func parseAlgs(hashAlg, sigAlg string) (crypto.Hash, string, error) {
	if strings.HasPrefix(hashAlg, NsXMLDsig) {
		hashAlg = hashAlg[len(NsXMLDsig):]
	} else if strings.HasPrefix(hashAlg, NsXMLDsigMore) {
		hashAlg = hashAlg[len(NsXMLDsigMore):]
	} else {
		return 0, "", errors.New("xmldsig: unsupported digest algorithm")
	}
	var hash crypto.Hash
	for h2, name := range hashNames {
		if hashAlg == name {
			hash = h2
			break
		}
	}
	if hash == 0 {
		return 0, "", errors.New("xmldsig: unsupported digest algorithm")
	}

	if strings.HasPrefix(sigAlg, NsXMLDsig) {
		sigAlg = sigAlg[len(NsXMLDsig):]
	} else if strings.HasPrefix(sigAlg, NsXMLDsigMore) {
		sigAlg = sigAlg[len(NsXMLDsigMore):]
	} else {
		return 0, "", errors.New("xmldsig: unsupported signature algorithm")
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

func parseKey(kv keyValue, pubtype string) (crypto.PublicKey, error) {
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
			return nil, fmt.Errorf("xmldsig: %s", err)
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
