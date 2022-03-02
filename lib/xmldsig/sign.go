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

// Implements a useful subset of the xmldsig specification for creating
// signatures over XML documents.
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

	"github.com/sassoftware/relic/lib/x509tools"

	"github.com/beevik/etree"
)

type SignOptions struct {
	// Use non-standard namespace for SHA-256 found in Microsoft ClickOnce manifests
	MsCompatHashNames bool
	// Use REC namespace for c14n method instead of the finalized one
	UseRecC14n bool
	// Add the X509 certificate chain to the KeyInfo
	IncludeX509 bool
	// Add a KeyValue element with the public key
	IncludeKeyValue bool
}

func (s SignOptions) c14nNamespace() string {
	if s.UseRecC14n {
		return AlgXMLExcC14nRec
	} else {
		return AlgXMLExcC14n
	}
}

// Create an enveloped signature from the document rooted at "root", replacing
// any existing signature and adding it as a last child of "parent".
func Sign(root, parent *etree.Element, hash crypto.Hash, privKey crypto.Signer, certs []*x509.Certificate, opts SignOptions) error {
	pubKey := privKey.Public()
	if len(certs) < 1 || !x509tools.SameKey(pubKey, certs[0].PublicKey) {
		return errors.New("xmldsig: first certificate must match private key")
	}
	RemoveElements(parent, "Signature")
	// canonicalize the enveloping document and digest it
	refDigest, err := hashCanon(root, hash)
	if err != nil {
		return err
	}
	hashAlg, sigAlg, err := hashAlgs(hash, pubKey, opts)
	if err != nil {
		return err
	}
	// build a signedinfo that references the enveloping document
	signature := parent.CreateElement("Signature")
	signature.CreateAttr("xmlns", NsXMLDsig)
	signedinfo := buildSignedInfo(signature, "", hashAlg, sigAlg, refDigest, opts)
	return finishSignature(signature, signedinfo, hash, privKey, certs, opts)
}

// Build an enveloping Signature document around the given Object element
func SignEnveloping(object *etree.Element, hash crypto.Hash, privKey crypto.Signer, certs []*x509.Certificate, opts SignOptions) (*etree.Element, error) {
	pubKey := privKey.Public()
	if len(certs) < 1 || !x509tools.SameKey(pubKey, certs[0].PublicKey) {
		return nil, errors.New("xmldsig: first certificate must match private key")
	}
	// insert the object into the signature element before canonicalizing so
	// that the namespace gets pushed down properly
	signature := etree.NewElement("Signature")
	signature.CreateAttr("xmlns", NsXMLDsig)
	signature.AddChild(object)
	refDigest, err := hashCanon(object, hash)
	if err != nil {
		return nil, err
	}
	hashAlg, sigAlg, err := hashAlgs(hash, pubKey, opts)
	if err != nil {
		return nil, err
	}
	if object.Tag != "Object" {
		return nil, errors.New("object must have tag \"Object\"")
	}
	refId := object.SelectAttrValue("Id", "")
	if refId == "" {
		return nil, errors.New("object lacks an Id attribute")
	}
	// build a signedinfo that references the enveloping document
	signedinfo := buildSignedInfo(signature, refId, hashAlg, sigAlg, refDigest, opts)
	// canonicalize the signedinfo section and sign it
	if err := finishSignature(signature, signedinfo, hash, privKey, certs, opts); err != nil {
		return nil, err
	}
	signature.RemoveChild(object)
	signature.AddChild(object)
	return signature, nil
}

func buildSignedInfo(signature *etree.Element, refId, hashAlg, sigAlg string, refDigest []byte, opts SignOptions) *etree.Element {
	signedinfo := signature.CreateElement("SignedInfo")
	signedinfo.CreateElement("CanonicalizationMethod").CreateAttr("Algorithm", opts.c14nNamespace())
	signedinfo.CreateElement("SignatureMethod").CreateAttr("Algorithm", sigAlg)
	reference := signedinfo.CreateElement("Reference")
	if refId == "" {
		reference.CreateAttr("URI", "")
	} else {
		reference.CreateAttr("URI", "#"+refId)
		reference.CreateAttr("Type", NsXMLDsig+"Object")
	}
	transforms := reference.CreateElement("Transforms")
	if refId == "" {
		transforms.CreateElement("Transform").CreateAttr("Algorithm", AlgDsigEnvelopedSignature)
	}
	transforms.CreateElement("Transform").CreateAttr("Algorithm", opts.c14nNamespace())
	reference.CreateElement("DigestMethod").CreateAttr("Algorithm", hashAlg)
	reference.CreateElement("DigestValue").SetText(base64.StdEncoding.EncodeToString(refDigest))
	return signedinfo
}

func finishSignature(signature, signedinfo *etree.Element, hash crypto.Hash, privKey crypto.Signer, certs []*x509.Certificate, opts SignOptions) error {
	siDigest, err := hashCanon(signedinfo, hash)
	if err != nil {
		return err
	}
	sig, err := privKey.Sign(rand.Reader, siDigest, hash)
	if err != nil {
		return err
	}
	// build the rest of the signature element
	if _, ok := privKey.Public().(*ecdsa.PublicKey); ok {
		// reformat the signature without ASN.1 structure
		esig, err := x509tools.UnmarshalEcdsaSignature(sig)
		if err != nil {
			return err
		}
		sig = esig.Pack()
	}
	signature.CreateElement("SignatureValue").SetText(base64.StdEncoding.EncodeToString(sig))
	keyinfo := etree.NewElement("KeyInfo")
	if opts.IncludeKeyValue {
		if err := addKeyInfo(keyinfo, privKey.Public()); err != nil {
			return err
		}
	}
	if opts.IncludeX509 && len(certs) > 0 {
		addCerts(keyinfo, certs)
	}
	if len(keyinfo.Child) > 0 {
		signature.AddChild(keyinfo)
	}
	return nil
}

func hashCanon(root *etree.Element, hash crypto.Hash) ([]byte, error) {
	canon, err := SerializeCanonical(root)
	if err != nil {
		return nil, fmt.Errorf("xmldsig: %w", err)
	}
	d := hash.New()
	d.Write(canon)
	return d.Sum(nil), nil
}

// Remove all child elements with this tag from the element
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

// Determine algorithm URIs for hashing and signing
func hashAlgs(hash crypto.Hash, pubKey crypto.PublicKey, opts SignOptions) (string, string, error) {
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
	if opts.MsCompatHashNames {
		hashAlg = NsXMLDsig + hashName
	} else {
		hashAlg = HashUris[hash]
	}
	if pubName == "rsa" && (hashName == "sha1" || opts.MsCompatHashNames) {
		sigAlg = NsXMLDsig + pubName + "-" + hashName
	} else {
		sigAlg = NsXMLDsigMore + pubName + "-" + hashName
	}
	return hashAlg, sigAlg, nil
}

// Add public key and optional X509 certificate chain to KeyInfo
func addKeyInfo(keyinfo *etree.Element, pubKey crypto.PublicKey) error {
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
		x := pk.CreateElement("X")
		x.CreateAttr("Value", k.X.String())
		x.CreateAttr("xmlns:xsi", NsXsi)
		x.CreateAttr("xsi:type", "PrimeFieldElemType")
		y := pk.CreateElement("Y")
		y.CreateAttr("Value", k.Y.String())
		y.CreateAttr("xmlns:xsi", NsXsi)
		y.CreateAttr("xsi:type", "PrimeFieldElemType")
	default:
		return errors.New("unsupported key type")
	}
	return nil
}

func addCerts(keyinfo *etree.Element, certs []*x509.Certificate) {
	x509data := keyinfo.CreateElement("X509Data")
	for _, cert := range certs {
		x509data.CreateElement("X509Certificate").SetText(base64.StdEncoding.EncodeToString(cert.Raw))
	}
}
