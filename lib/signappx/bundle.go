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

package signappx

import (
	"archive/zip"
	"bytes"
	"crypto/x509"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/beevik/etree"

	"github.com/sassoftware/relic/v7/lib/x509tools"
)

type bundleManifest struct {
	XMLName       xml.Name `xml:"http://schemas.microsoft.com/appx/2013/bundle Bundle"`
	SchemaVersion string   `xml:",attr"`

	Identity appxIdentity
	Packages []bundlePackage `xml:"Packages>Package"`

	Etree *etree.Document `xml:"-"`
}

type bundlePackage struct {
	Type         string `xml:",attr"`
	Version      string `xml:",attr"`
	Architecture string `xml:",attr"`
	FileName     string `xml:",attr"`
	Offset       int64  `xml:",attr"`
	Size         uint64 `xml:",attr"`
}

func verifyBundle(r io.ReaderAt, files zipFiles, sig *AppxSignature, skipDigests bool) error {
	blob, err := readZipFile(files[bundleManifestFile])
	if err != nil {
		return fmt.Errorf("bundle manifest: %w", err)
	}
	var bundle bundleManifest
	if err := xml.Unmarshal(blob, &bundle); err != nil {
		return fmt.Errorf("bundle manifest: %w", err)
	}
	packages := make(map[string]int)
	for i, pkg := range bundle.Packages {
		packages[pkg.FileName] = i
	}
	sig.Bundled = make(map[string]*AppxSignature)
	publisher := x509tools.FormatPkixName(sig.Signature.Certificate.RawSubject, x509tools.NameStyleMsOsco)
	if bundle.Identity.Publisher != publisher {
		return fmt.Errorf("bundle manifest: publisher identity mismatch:\nexpected: %s\nactual: %s", publisher, bundle.Identity.Publisher)
	}
	for _, zf := range files {
		if !strings.HasSuffix(zf.Name, ".appx") {
			continue
		}
		if zf.Method != zip.Store {
			return errors.New("bundle manifest: contains compressed appx")
		}
		dosname := strings.ReplaceAll(zf.Name, "/", "\\")
		pkgIndex, ok := packages[dosname]
		if !ok {
			return fmt.Errorf("bundle manifest: missing file %s", zf.Name)
		}
		packages[dosname] = -1 // mark as seen
		pkg := bundle.Packages[pkgIndex]

		offset, err := zf.DataOffset()
		if err != nil {
			return fmt.Errorf("bundle manifest: %w", err)
		}
		if pkg.Offset != offset {
			return fmt.Errorf("bundle manifest: %s claimed offset of %d but actual offset is %d", zf.Name, pkg.Offset, offset)
		} else if pkg.Size != zf.UncompressedSize64 {
			return fmt.Errorf("bundle manifest: %s claimed size of %d but actual size is %d", zf.Name, pkg.Size, zf.UncompressedSize64)
		}
		nested := io.NewSectionReader(r, offset, int64(zf.UncompressedSize64))
		nestedSig, err := Verify(nested, int64(zf.UncompressedSize64), skipDigests)
		if err != nil {
			return fmt.Errorf("bundled file %s: %w", zf.Name, err)
		}
		if !bytes.Equal(nestedSig.Signature.Certificate.Raw, sig.Signature.Certificate.Raw) {
			return fmt.Errorf("bundled file %s signed by different publisher", zf.Name)
		}
		sig.Bundled[zf.Name] = nestedSig
	}
	for name, unseen := range packages {
		if unseen >= 0 {
			return fmt.Errorf("bundle missing file: %s", name)
		}
	}
	return nil
}

func parseBundle(blob []byte) (*bundleManifest, error) {
	manifest := new(bundleManifest)
	if err := xml.Unmarshal(blob, manifest); err != nil {
		return nil, err
	}
	manifest.Etree = etree.NewDocument()
	if err := manifest.Etree.ReadFromBytes(blob); err != nil {
		return nil, err
	}
	return manifest, nil
}

func (m *bundleManifest) SetPublisher(cert *x509.Certificate) {
	subj := x509tools.FormatPkixName(cert.RawSubject, x509tools.NameStyleMsOsco)
	m.Identity.Publisher = subj
	el := m.Etree.FindElement("Bundle/Identity")
	if el != nil {
		el.CreateAttr("Publisher", subj)
	}
}

func (m *bundleManifest) Marshal() ([]byte, error) {
	return m.Etree.WriteToBytes()
}
