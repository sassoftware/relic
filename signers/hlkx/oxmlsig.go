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

package hlkx

import (
	"crypto/hmac"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"

	"github.com/beevik/etree"

	"github.com/mind-security/relic/v8/lib/certloader"
	"github.com/mind-security/relic/v8/lib/pkcs7"
	"github.com/mind-security/relic/v8/lib/pkcs9"
	"github.com/mind-security/relic/v8/lib/xmldsig"
	"github.com/mind-security/relic/v8/signers"
	"github.com/mind-security/relic/v8/signers/sigerrors"
)

type oxmlManifest struct {
	References []reference `xml:"Manifest>Reference"`
	Properties []property  `xml:"SignatureProperties>SignatureProperty"`
}

type reference struct {
	URI          string   `xml:",attr"`
	Transforms   []method `xml:"Transforms>Transform"`
	DigestMethod method
	DigestValue  string
}

type method struct {
	Algorithm string `xml:",attr"`
}

type property struct {
	Id                  string `xml:",attr"`
	SignatureTimeFormat string `xml:"SignatureTime>Format"`
	SignatureTimeValue  string `xml:"SignatureTime>Value"`
}

func checkManifest(files zipFiles, manifest *etree.Element) error {
	doc := etree.NewDocument()
	doc.SetRoot(manifest.Copy())
	blob, err := doc.WriteToBytes()
	if err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}
	var m oxmlManifest
	if err := xml.Unmarshal(blob, &m); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}
	for _, ref := range m.References {
		p := path.Join("./" + ref.URI)
		i := strings.IndexByte(p, '?')
		if i >= 0 {
			p = p[:i]
		}
		zf := files[p]
		if zf == nil {
			return fmt.Errorf("validation failed: file not found: %s", p)
		}
		f, err := zf.Open()
		if err != nil {
			return fmt.Errorf("validation failed: %w", err)
		}
		_, hash := xmldsig.HashAlgorithm(ref.DigestMethod.Algorithm)
		if !hash.Available() {
			return errors.New("validation failed: unsupported digest algorithm")
		}
		d := hash.New()
		if _, err := io.Copy(d, f); err != nil {
			return err
		}
		refCalc := d.Sum(nil)
		refv, err := base64.StdEncoding.DecodeString(ref.DigestValue)
		if err != nil {
			return errors.New("validation failed: invalid digest")
		}
		if !hmac.Equal(refv, refCalc) {
			return fmt.Errorf("validation failed: digest mismatch for %s: calculated %x, found %x", p, refCalc, refv)
		}
	}
	return nil
}

func checkTimestamp(root *etree.Element, encryptedDigest []byte) (*pkcs9.CounterSignature, error) {
	tsEl := root.FindElement("Object/TimeStamp/EncodedTime")
	if tsEl == nil {
		return nil, nil
	}
	blob, err := base64.StdEncoding.DecodeString(tsEl.Text())
	if err != nil {
		return nil, fmt.Errorf("timestamp check failed: %w", err)
	}
	tst, err := pkcs7.Unmarshal(blob)
	if err != nil {
		return nil, fmt.Errorf("timestamp check failed: %w", err)
	}
	return pkcs9.Verify(tst, encryptedDigest, nil)
}

// calcCertFileName derives the certificate filename used inside the HLKX package.
// HLKX uses the big-endian hex of the serial number (matching .NET's reversed little-endian
// GetSerialNumber() output) as the base name.
func calcCertFileName(cert *x509.Certificate) string {
	return strings.ToUpper(hex.EncodeToString(cert.SerialNumber.Bytes()))
}

func readSignature(files zipFiles) ([]byte, []*x509.Certificate, error) {
	top := relPath("")
	if files[top] == nil {
		return nil, nil, sigerrors.NotSignedError{Type: "hlkx"}
	}
	// top rels file
	r, err := parseRels(files, top)
	if err != nil {
		return nil, nil, err
	}
	origin := r.Find(sigOriginType)
	if origin == "" {
		return nil, nil, sigerrors.NotSignedError{Type: "hlkx"}
	}
	// signature rels file
	r, err = parseRels(files, relPath(origin))
	if err != nil {
		return nil, nil, err
	}
	sigpath := r.Find(sigType)
	if sigpath == "" {
		return nil, nil, sigerrors.NotSignedError{Type: "hlkx"}
	}
	sigblob, err := readZip(files, sigpath)
	if err != nil {
		return nil, nil, err
	}
	// certificates (optional)
	var certs []*x509.Certificate
	if files[relPath(sigpath)] != nil {
		r, err := parseRels(files, relPath(sigpath))
		if err != nil {
			return nil, nil, err
		}
		for _, rel := range r.Relationship {
			if rel.Type != certType {
				continue
			}
			p := path.Clean("./" + rel.Target)
			blob, err := readZip(files, p)
			if err != nil {
				return nil, nil, err
			}
			certs2, err := x509.ParseCertificates(blob)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to parse certificate %s: %w", p, err)
			}
			certs = append(certs, certs2...)
		}
	}
	return sigblob, certs, nil
}

func (m *mangler) makeSignature(cert *certloader.Certificate, opts signers.SignOpts) ([]byte, error) {
	hashUri := xmldsig.HashUris[opts.Hash]
	if hashUri == "" {
		return nil, errors.New("unsupported digest algorithm")
	}
	pkg := etree.NewElement("Object")
	pkg.CreateAttr("Id", "idPackageObject")
	// file manifest
	manifest := pkg.CreateElement("Manifest")
	names := make([]string, 0, len(m.digests)+1)
	for name := range m.digests {
		names = append(names, name)
	}
	// Include _rels/.rels via RelationshipTransform, sorted into its natural position.
	if m.rootRelsRef != nil {
		names = append(names, "_rels/.rels")
	}
	sort.Strings(names)
	for _, name := range names {
		// Special Reference for _rels/.rels: OPC RelationshipTransform + C14N.
		if name == "_rels/.rels" && m.rootRelsRef != nil {
			ref := manifest.CreateElement("Reference")
			ref.CreateAttr("URI", "/_rels/.rels?ContentType="+contentTypes["rels"])
			transforms := ref.CreateElement("Transforms")
			relTr := transforms.CreateElement("Transform")
			relTr.CreateAttr("Algorithm", relTransformAlg)
			relTr.CreateAttr("xmlns:opc", nsDigSig)
			for _, st := range m.rootRelsRef.sourceTypes {
				grp := relTr.CreateElement("opc:RelationshipsGroupReference")
				grp.CreateAttr("SourceType", st)
			}
			transforms.CreateElement("Transform").CreateAttr("Algorithm", c14nAlg)
			ref.CreateElement("DigestMethod").CreateAttr("Algorithm", hashUri)
			ref.CreateElement("DigestValue").SetText(base64.StdEncoding.EncodeToString(m.rootRelsRef.digest))
			continue
		}
		digest := m.digests[name]
		ctype := m.ctypes.Find(name)
		if ctype == "" {
			ext := path.Ext(path.Base(name))
			if len(ext) > 0 && ext[0] == '.' {
				ctype = contentTypes[ext[1:]]
			}
		}
		if ctype == "" {
			ctype = defaultContentType
		}
		ref := manifest.CreateElement("Reference")
		ref.CreateAttr("URI", "/"+name+"?ContentType="+ctype)
		ref.CreateElement("DigestMethod").CreateAttr("Algorithm", hashUri)
		ref.CreateElement("DigestValue").SetText(base64.StdEncoding.EncodeToString(digest))
	}
	// signature time
	props := pkg.CreateElement("SignatureProperties")
	proptime := props.CreateElement("SignatureProperty")
	proptime.CreateAttr("Id", "idSignatureTime")
	proptime.CreateAttr("Target", "")
	sigtime := proptime.CreateElement("SignatureTime")
	sigtime.CreateAttr("xmlns", nsDigSig)
	sigtime.CreateElement("Format").SetText(tsFormatXML)
	sigtime.CreateElement("Value").SetText(opts.Time.Format(tsFormatGo))
	// sign — HLKX always embeds certs separately, so IncludeX509 is false
	xopts := xmldsig.SignOptions{UseRecC14n: true, IncludeKeyValue: true}
	sigel, err := xmldsig.SignEnveloping(pkg, opts.Hash, cert.Signer(), cert.Chain(), xopts)
	if err != nil {
		return nil, err
	}
	// timestamp
	if cert.Timestamper != nil {
		encryptedDigest, _ := base64.StdEncoding.DecodeString(sigel.SelectElement("SignatureValue").Text())
		req := &pkcs9.Request{EncryptedDigest: encryptedDigest, Hash: opts.Hash}
		tst, err := cert.Timestamper.Timestamp(opts.Context(), req)
		if err != nil {
			return nil, fmt.Errorf("failed to timestamp signature: %w", err)
		}
		blob, err := tst.Marshal()
		if err != nil {
			return nil, fmt.Errorf("failed to timestamp signature: %w", err)
		}
		tsob := sigel.CreateElement("Object")
		tsob.CreateAttr("xmlns", xmldsig.NsXMLDsig)
		ts := tsob.CreateElement("TimeStamp")
		ts.CreateAttr("xmlns", nsDigSig)
		ts.CreateAttr("Id", "idSignatureTimestamp")
		ts.CreateElement("Comment")
		ts.CreateElement("EncodedTime").SetText(base64.StdEncoding.EncodeToString(blob))
	}
	doc := etree.NewDocument()
	doc.SetRoot(sigel)
	body, err := doc.WriteToBytes()
	if err != nil {
		return nil, err
	}
	// HLKX signature files start with an XML declaration including standalone="yes"
	result := make([]byte, 0, len(xmlDeclaration)+len(body))
	result = append(result, []byte(xmlDeclaration)...)
	result = append(result, body...)
	return result, nil
}
