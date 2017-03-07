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

package appmanifest

import (
	"crypto"
	"encoding/base64"
	"encoding/hex"
	"errors"

	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/certloader"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/xmldsig"
	"github.com/beevik/etree"
)

const (
	NsMsRel        = "http://schemas.microsoft.com/windows/rel/2005/reldata"
	NsMpeg21       = "urn:mpeg:mpeg21:2003:01-REL-R-NS"
	NsAuthenticode = "http://schemas.microsoft.com/windows/pki/2005/Authenticode"
)

type ManifestSignature struct {
	Signed []byte
}

func Sign(manifest []byte, cert *certloader.Certificate, opts crypto.SignerOpts) (*ManifestSignature, error) {
	doc := etree.NewDocument()
	if err := doc.ReadFromString(string(manifest)); err != nil {
		return nil, err
	}
	root := doc.Root()
	// Update signer-related attributes
	asi, err := setAssemblyIdentity(root, cert)
	if err != nil {
		return nil, err
	}
	subjectName, err := setPublisherIdentity(root, cert)
	if err != nil {
		return nil, err
	}
	// Primary signature
	sigopts := xmldsig.XmlSignOptions{MsCompatHashNames: true}
	if err := xmldsig.Sign(doc, root, opts.HashFunc(), cert.Signer(), cert.Chain(), sigopts); err != nil {
		return nil, err
	}
	sig, keyinfo := setSigIds(root, "StrongNameSignature", "StrongNameKeyInfo")
	// Create authenticode structure
	manifestHash := makeManifestHash(sig)
	authDoc, sigDestNode := makeLicense(asi, subjectName, manifestHash)
	// Sign authenticode structure
	sigopts.IncludeX509 = true
	if err := xmldsig.Sign(authDoc, sigDestNode, opts.HashFunc(), cert.Signer(), cert.Chain(), sigopts); err != nil {
		return nil, err
	}
	setSigIds(sigDestNode, "AuthenticodeSignature", "")
	// Attach authenticode to the primary document
	license := authDoc.Root()
	license.AddChild(sigDestNode)
	reldata := keyinfo.CreateElement("msrel:RelData")
	reldata.CreateAttr("xmlns:msrel", NsMsRel)
	reldata.AddChild(license)
	// Serialize
	signed, err := doc.WriteToBytes()
	if err != nil {
		return nil, err
	}
	return &ManifestSignature{Signed: signed}, nil
}

func setAssemblyIdentity(root *etree.Element, cert *certloader.Certificate) (*etree.Element, error) {
	token, err := PublicKeyToken(cert.Leaf.PublicKey)
	if err != nil {
		return nil, err
	}
	var asi *etree.Element
	for _, elem := range root.ChildElements() {
		if elem.Tag == "assemblyIdentity" {
			asi = elem
			break
		}
	}
	if asi == nil {
		return nil, errors.New("manifest has no top-level assemblyIdentity element")
	}
	asi.CreateAttr("publicKeyToken", token)
	return asi, nil
}

func setPublisherIdentity(root *etree.Element, cert *certloader.Certificate) (string, error) {
	// add or replace publisherIdentity
	subjectName, issuerKeyHash, err := PublisherIdentity(cert)
	if err != nil {
		return "", err
	}
	xmldsig.RemoveElements(root, "publisherIdentity")
	ident := root.CreateElement("publisherIdentity")
	ident.CreateAttr("name", subjectName)
	ident.CreateAttr("issuerKeyHash", issuerKeyHash)
	return subjectName, nil
}

func makeLicense(asi *etree.Element, subjectName, manifestHash string) (*etree.Document, *etree.Element) {
	license := etree.NewElement("r:license")
	license.CreateAttr("xmlns:r", NsMpeg21)
	license.CreateAttr("xmlns:as", NsAuthenticode)

	grant := license.CreateElement("r:grant")
	minfo := grant.CreateElement("as:ManifestInformation")
	minfo.CreateAttr("Hash", manifestHash)
	minfo.CreateAttr("Description", "")
	minfo.CreateAttr("Url", "")
	massy := asi.Copy()
	massy.Space = "as"
	minfo.AddChild(massy)
	grant.CreateElement("as:SignedBy")
	grant.CreateElement("as:AuthenticodePublisher").CreateElement("as:X509SubjectName").SetText(subjectName) // TODO check this

	issuer := license.CreateElement("r:issuer")
	licensedoc := etree.NewDocument()
	licensedoc.SetRoot(license)
	return licensedoc, issuer
}

func makeManifestHash(sig *etree.Element) string {
	dv := sig.FindElement("//DigestValue")
	blob, _ := base64.StdEncoding.DecodeString(dv.Text())
	// little-endian is so great, why not apply it to SHA hashes?
	for i := 0; i < len(blob)/2; i++ {
		j := len(blob) - i - 1
		blob[i], blob[j] = blob[j], blob[i]
	}
	return hex.EncodeToString(blob)
}

func setSigIds(root *etree.Element, sigName, keyinfoName string) (sig, keyinfo *etree.Element) {
	sig = root.SelectElement("Signature")
	if sigName != "" {
		sig.CreateAttr("Id", sigName)
	}
	keyinfo = sig.SelectElement("KeyInfo")
	if keyinfoName != "" {
		keyinfo.CreateAttr("Id", keyinfoName)
	}
	return sig, keyinfo
}
