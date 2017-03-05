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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"

	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/x509tools"

	"github.com/beevik/etree"
)

const (
	NsXmlDsig     = "http://www.w3.org/2000/09/xmldsig#"
	NsXmlDsigMore = "http://www.w3.org/2001/04/xmldsig-more#"
	AlgXmlExcC14n = "http://www.w3.org/2001/10/xml-exc-c14n#"

	AlgDsigEnvelopedSignature = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
)

type XmlSignOptions struct {
	MsCompatHashNames bool
	IncludeX509       bool
}

var hashNames = map[crypto.Hash]string{
	crypto.SHA1:   "sha1",
	crypto.SHA224: "sha224",
	crypto.SHA256: "sha256",
	crypto.SHA384: "sha384",
	crypto.SHA512: "sha512",
}

func Sign(doc *etree.Document, parent *etree.Element, hash crypto.Hash, privKey crypto.Signer, certs []*x509.Certificate, opts XmlSignOptions) error {
	pubKey := privKey.Public()
	if len(certs) < 1 || !x509tools.SameKey(pubKey, certs[0].PublicKey) {
		return errors.New("xmldsig: first certificate must match private key")
	}
	root := doc.Root()
	RemoveElements(parent, "Signature")
	// canonicalize the enveloping document and digest it
	refDigest, err := hashCanon(root, hash)
	hashAlg, sigAlg, err := hashAlgs(hash, pubKey, opts)
	if err != nil {
		return err
	}
	// build a signedinfo that references the enveloping document
	signature := parent.CreateElement("Signature")
	signature.CreateAttr("xmlns", NsXmlDsig)
	signedinfo := signature.CreateElement("SignedInfo")
	signedinfo.CreateElement("CanonicalizationMethod").CreateAttr("Algorithm", AlgXmlExcC14n)
	signedinfo.CreateElement("SignatureMethod").CreateAttr("Algorithm", sigAlg)
	reference := signedinfo.CreateElement("Reference")
	reference.CreateAttr("URI", "")
	transforms := reference.CreateElement("Transforms")
	transforms.CreateElement("Transform").CreateAttr("Algorithm", AlgDsigEnvelopedSignature)
	transforms.CreateElement("Transform").CreateAttr("Algorithm", AlgXmlExcC14n)
	reference.CreateElement("DigestMethod").CreateAttr("Algorithm", hashAlg)
	reference.CreateElement("DigestValue").SetText(base64.StdEncoding.EncodeToString(refDigest))
	// canonicalize the signedinfo section and sign it
	siDigest, err := hashCanon(signedinfo, hash)
	sig, err := privKey.Sign(rand.Reader, siDigest, hash)
	if err != nil {
		return err
	}
	// build the rest of the signature element
	signature.CreateElement("SignatureValue").SetText(base64.StdEncoding.EncodeToString(sig))
	keyinfo := signature.CreateElement("KeyInfo")
	addcerts := certs
	if !opts.IncludeX509 {
		addcerts = nil
	}
	if err := addKeyInfo(keyinfo, pubKey, addcerts); err != nil {
		return err
	}
	return nil
}

func hashCanon(root *etree.Element, hash crypto.Hash) ([]byte, error) {
	canon, err := SerializeCanonical(root)
	if err != nil {
		return nil, err
	}
	d := hash.New()
	d.Write(canon)
	return d.Sum(nil), nil
}

func RemoveElements(root *etree.Element, tag string) {
	for i := 0; i < len(root.Child); {
		token := root.Child[i]
		if elem, ok := token.(*etree.Element); ok && elem.Tag == tag {
			root.Child = append(root.Child[:i], root.Child[i+1:]...)
		} else {
			i++
		}
	}
}

func hashAlgs(hash crypto.Hash, pubKey crypto.PublicKey, opts XmlSignOptions) (string, string, error) {
	hashName := hashNames[hash]
	if hashName == "" {
		return "", "", errors.New("unsupported hash type")
	}
	var pubName string
	switch pubKey.(type) {
	case *rsa.PublicKey:
		pubName = "rsa"
	case *ecdsa.PublicKey:
		pubName = "ecdsa"
	default:
		return "", "", errors.New("unsupported key type")
	}
	var hashAlg, sigAlg string
	if hashName == "sha1" || opts.MsCompatHashNames {
		hashAlg = NsXmlDsig + hashName
	} else {
		hashAlg = NsXmlDsigMore + hashName
	}
	if pubName == "rsa" && (hashName == "sha1" || opts.MsCompatHashNames) {
		sigAlg = NsXmlDsig + pubName + "-" + hashName
	} else {
		sigAlg = NsXmlDsigMore + pubName + "-" + hashName
	}
	return hashAlg, sigAlg, nil
}

func addKeyInfo(keyinfo *etree.Element, pubKey crypto.PublicKey, certs []*x509.Certificate) error {
	keyvalue := keyinfo.CreateElement("KeyValue")
	switch k := pubKey.(type) {
	case *rsa.PublicKey:
		e := big.NewInt(int64(k.E))
		rkv := keyvalue.CreateElement("RSAKeyValue")
		rkv.CreateElement("Modulus").SetText(base64.StdEncoding.EncodeToString(k.N.Bytes()))
		rkv.CreateElement("Exponent").SetText(base64.StdEncoding.EncodeToString(e.Bytes()))
	case *ecdsa.PublicKey:
		curve, err := x509tools.CurveByCurve(k.Curve)
		if err != nil {
			return err
		}
		curveUrn := fmt.Sprintf("urn:oid:%s", curve.Oid)
		ekv := keyvalue.CreateElement("ECDSAKeyValue")
		ekv.CreateElement("DomainParameters").CreateElement("NamedCurve").CreateAttr("URN", curveUrn)
		pk := ekv.CreateElement("PublicKey")
		pk.CreateElement("X").CreateAttr("Value", k.X.String())
		pk.CreateElement("Y").CreateAttr("Value", k.Y.String())
	default:
		return errors.New("unsupported key type")
	}
	if len(certs) > 0 {
		x509data := keyinfo.CreateElement("X509Data")
		for _, cert := range certs {
			x509data.CreateElement("X509Certificate").SetText(base64.StdEncoding.EncodeToString(cert.Raw))
		}
	}
	return nil
}
