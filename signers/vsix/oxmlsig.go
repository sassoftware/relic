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

package vsix

import (
	"crypto"
	"crypto/hmac"
	"crypto/x509"
	"encoding/base32"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"

	"github.com/beevik/etree"

	"github.com/sassoftware/relic/v7/lib/certloader"
	"github.com/sassoftware/relic/v7/lib/pkcs7"
	"github.com/sassoftware/relic/v7/lib/pkcs9"
	"github.com/sassoftware/relic/v7/lib/xmldsig"
	"github.com/sassoftware/relic/v7/signers"
	"github.com/sassoftware/relic/v7/signers/sigerrors"
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

// looks sorta like the official vsixsigntool output, close enough
func calcFileName(cert *x509.Certificate) string {
	d := crypto.SHA1.New()
	d.Write(cert.Raw)
	sum := d.Sum(nil)
	return strings.ToLower(base32.StdEncoding.EncodeToString(sum))[:25]
}

func readSignature(files zipFiles) ([]byte, []*x509.Certificate, error) {
	top := relPath("")
	if files[top] == nil {
		return nil, nil, sigerrors.NotSignedError{Type: "vsix"}
	}
	// top rels file
	r, err := parseRels(files, top)
	if err != nil {
		return nil, nil, err
	}
	origin := r.Find(sigOriginType)
	if origin == "" {
		return nil, nil, sigerrors.NotSignedError{Type: "vsix"}
	}
	// signature rels file
	r, err = parseRels(files, relPath(origin))
	if err != nil {
		return nil, nil, err
	}
	sigpath := r.Find(sigType)
	if sigpath == "" {
		return nil, nil, sigerrors.NotSignedError{Type: "vsix"}
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

func (m *mangler) makeSignature(cert *certloader.Certificate, opts signers.SignOpts, detachCerts bool) ([]byte, error) {
	hashUri := xmldsig.HashUris[opts.Hash]
	if hashUri == "" {
		return nil, errors.New("unsupported digest algorithm")
	}
	pkg := etree.NewElement("Object")
	pkg.CreateAttr("Id", "idPackageObject")
	// file manifest
	manifest := pkg.CreateElement("Manifest")
	names := make([]string, 0, len(m.digests))
	for name := range m.digests {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		digest := m.digests[name]
		ctype := m.ctypes.Find(name)
		if ctype == "" {
			ext := path.Ext(path.Base(name))
			if ext[0] == '.' {
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
	// sign
	xopts := xmldsig.SignOptions{UseRecC14n: true, IncludeKeyValue: true}
	if !detachCerts {
		xopts.IncludeX509 = true
	}
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
	return doc.WriteToBytes()
}
