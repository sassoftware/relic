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

package appmanifest

import (
	"bytes"
	"crypto"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/beevik/etree"

	"github.com/sassoftware/relic/v7/lib/certloader"
	"github.com/sassoftware/relic/v7/lib/pkcs7"
	"github.com/sassoftware/relic/v7/lib/pkcs9"
	"github.com/sassoftware/relic/v7/lib/xmldsig"
)

const (
	NsMsRel        = "http://schemas.microsoft.com/windows/rel/2005/reldata"
	NsMpeg21       = "urn:mpeg:mpeg21:2003:01-REL-R-NS"
	NsAuthenticode = "http://schemas.microsoft.com/windows/pki/2005/Authenticode"
)

type SignedManifest struct {
	ManifestSignature
	Signed          []byte
	EncryptedDigest []byte
}

// Sign an application manifest
func Sign(manifest []byte, cert *certloader.Certificate, opts crypto.SignerOpts) (*SignedManifest, error) {
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
	sigopts := xmldsig.SignOptions{MsCompatHashNames: true, IncludeKeyValue: true}
	if err := xmldsig.Sign(root, root, opts.HashFunc(), cert.Signer(), cert.Chain(), sigopts); err != nil {
		return nil, err
	}
	sig, keyinfo := setSigIds(root, "StrongNameSignature", "StrongNameKeyInfo")
	// Create authenticode structure
	manifestHash := makeManifestHash(sig)
	license, sigDestNode := makeLicense(asi, subjectName, manifestHash)
	// Sign authenticode structure
	sigopts.IncludeX509 = true
	if err := xmldsig.Sign(license, sigDestNode, opts.HashFunc(), cert.Signer(), cert.Chain(), sigopts); err != nil {
		return nil, err
	}
	aSig, _ := setSigIds(sigDestNode, "AuthenticodeSignature", "")
	// Attach authenticode to the primary document
	license.AddChild(sigDestNode)
	reldata := keyinfo.CreateElement("msrel:RelData")
	reldata.CreateAttr("xmlns:msrel", NsMsRel)
	reldata.AddChild(license)
	// Serialize
	signed, err := doc.WriteToBytes()
	if err != nil {
		return nil, err
	}
	// Get authenticode signature value for timestamping
	encryptedDigest, _ := base64.StdEncoding.DecodeString(aSig.SelectElement("SignatureValue").Text())
	return &SignedManifest{
		Signed:          signed,
		EncryptedDigest: encryptedDigest,
		ManifestSignature: ManifestSignature{
			Signature: &pkcs9.TimestampedSignature{Signature: pkcs7.Signature{
				Certificate:   cert.Leaf,
				Intermediates: cert.Chain(),
			}},
			AssemblyName:    asi.SelectAttrValue("name", ""),
			AssemblyVersion: asi.SelectAttrValue("version", ""),
			Hash:            opts.HashFunc(),
			PublicKeyToken:  asi.SelectAttrValue("publicKeyToken", ""),
		}}, nil
}

// Update the assemblyIdentity element with the actual signer public key. Only
// the top-level one is updated, not the ones underneath individual manifest
// entries.
func setAssemblyIdentity(root *etree.Element, cert *certloader.Certificate) (*etree.Element, error) {
	token, err := PublicKeyToken(cert.Leaf.PublicKey)
	if err != nil {
		return nil, err
	}
	asi := root.SelectElement("assemblyIdentity")
	if asi == nil {
		return nil, errors.New("manifest has no top-level assemblyIdentity element")
	}
	asi.CreateAttr("publicKeyToken", token)
	return asi, nil
}

// Add/replace the publisherIdentity element
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

// Create the "license" block that goes inside the inner signature
func makeLicense(asi *etree.Element, subjectName, manifestHash string) (*etree.Element, *etree.Element) {
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
	grant.CreateElement("as:AuthenticodePublisher").CreateElement("as:X509SubjectName").SetText(subjectName)

	issuer := license.CreateElement("r:issuer")
	return license, issuer
}

// ManifestInformation contains a hash value which is, for some inane reason,
// the same hash that the outer signature references but in reverse byte order.
func makeManifestHash(sig *etree.Element) string {
	dv := sig.FindElement(".//DigestValue")
	blob, _ := base64.StdEncoding.DecodeString(dv.Text())
	for i := 0; i < len(blob)/2; i++ {
		j := len(blob) - i - 1
		blob[i], blob[j] = blob[j], blob[i]
	}
	return hex.EncodeToString(blob)
}

// Set Id attributes on signature elements
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

// Attach a timestamp counter-signature
func (m *SignedManifest) AddTimestamp(token *pkcs7.ContentInfoSignedData) error {
	doc := etree.NewDocument()
	if err := doc.ReadFromString(string(m.Signed)); err != nil {
		return err
	}
	aSig := doc.Root().FindElement("Signature/KeyInfo/msrel:RelData/r:license/r:issuer/Signature")
	if aSig == nil {
		return errors.New("manifest has no authenticode signature")
	}
	siblob, err := token.Marshal()
	if err != nil {
		return err
	}
	lines := (47 + len(siblob)) / 48
	buf := bytes.NewBuffer(make([]byte, 0, (64+2)*lines))
	for len(siblob) > 0 {
		n := len(siblob)
		if n > 48 {
			n = 48
		}
		chunk := siblob[:n]
		siblob = siblob[n:]

		buf.WriteString(base64.StdEncoding.EncodeToString(chunk))
		buf.WriteString("\r\n")
	}
	aSig.CreateElement("Object").CreateElement("as:Timestamp").SetText(buf.String())
	signed, err := doc.WriteToBytes()
	if err != nil {
		return err
	}
	cs, err := VerifyTimestamp(token, m.EncryptedDigest, m.Signature.Intermediates)
	if err != nil {
		return fmt.Errorf("failed to validate timestamp: %w", err)
	}
	m.Signed = signed
	m.Signature.CounterSignature = cs
	return nil
}
