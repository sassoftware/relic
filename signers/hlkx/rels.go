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
	"bytes"
	"crypto"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"path"

	"github.com/mind-security/relic/v8/lib/certloader"
)

type oxfRelationships struct {
	XMLName      xml.Name `xml:"http://schemas.openxmlformats.org/package/2006/relationships Relationships"`
	Relationship []oxfRelationship
}

// HLKX requires Type before Target (unlike VSIX which uses Target, Id, Type)
type oxfRelationship struct {
	Type   string `xml:",attr"`
	Target string `xml:",attr"`
	Id     string `xml:",attr"`
}

func readZip(files zipFiles, path string) ([]byte, error) {
	zf := files[path]
	if zf == nil {
		return nil, fmt.Errorf("file missing from zip: %s", path)
	}
	f, err := zf.Open()
	if err != nil {
		return nil, fmt.Errorf("failed to read zip file %s: %w", path, err)
	}
	return ioutil.ReadAll(f)
}

func parseRels(files zipFiles, path string) (*oxfRelationships, error) {
	blob, err := readZip(files, path)
	if err != nil {
		return nil, err
	}
	rels := new(oxfRelationships)
	if err := xml.Unmarshal(blob, rels); err != nil {
		return nil, fmt.Errorf("error parsing rels: %w", err)
	}
	return rels, nil
}

func (rels *oxfRelationships) Find(rType string) string {
	for _, rel := range rels.Relationship {
		if rel.Type == rType {
			return path.Clean("./" + rel.Target)
		}
	}
	return ""
}

func (rels *oxfRelationships) Append(zipPath, relType string) {
	d := crypto.SHA1.New()
	d.Write([]byte(zipPath))
	d.Write([]byte(relType))
	rel := oxfRelationship{Type: relType, Target: path.Clean("/" + zipPath)}
	for {
		rel.Id = fmt.Sprintf("R%X", d.Sum(nil)[:4])
		ok := true
		for _, rel2 := range rels.Relationship {
			if rel2.Id == rel.Id {
				ok = false
			}
		}
		if ok {
			break
		}
		d.Write([]byte{0})
	}
	rels.Relationship = append(rels.Relationship, rel)
}

func (rels *oxfRelationships) Marshal() ([]byte, error) {
	x, err := xml.Marshal(rels)
	if err != nil {
		return nil, err
	}
	// Convert Go's explicit closing tags to self-closing for empty elements,
	// matching what Windows OPC tooling produces.
	x = bytes.ReplaceAll(x, []byte("></Relationship>"), []byte("/>"))
	// Use opcXMLDecl (no standalone, no trailing newline) so the root element
	// immediately follows the declaration, as required by OPC tooling.
	ret := append([]byte(opcXMLDecl), x...)
	return ret, nil
}

func relPath(fp string) string {
	base := path.Base(fp)
	if base == "." {
		base = ""
	}
	return path.Join(path.Dir(fp), "_rels", base+".rels")
}

func (m *mangler) addFile(name string, contents []byte) error {
	d := m.hash.New()
	d.Write(contents)
	m.digests[name] = d.Sum(nil)
	return m.m.NewFile(name, contents)
}

// addFileNoDigest adds a file to the zip without adding it to the signature manifest
func (m *mangler) addFileNoDigest(name string, contents []byte) error {
	return m.m.NewFile(name, contents)
}

func (m *mangler) newRels(parent, child, relType string) error {
	var rels oxfRelationships
	// When rewriting the root rels file, preserve all pre-existing non-signature relationships
	// so that HLKX-specific relationships (e.g. WTT manifest links) are not stripped.
	if parent == "" && m.rootRels != nil {
		for _, rel := range m.rootRels.Relationship {
			if rel.Type != sigOriginType {
				rels.Relationship = append(rels.Relationship, rel)
			}
		}
	}
	rels.Append(child, relType)
	contents, err := rels.Marshal()
	if err != nil {
		return err
	}
	// Root rels uses RelationshipTransform (computed via computeRootRelsRef),
	// not a plain digest, so do not add it to m.digests.
	// But also compute a plain C14N digest for the additional manifest reference
	// that covers the entire _rels/.rels (including the origin relationship).
	if parent == "" {
		c14nDigest, err := m.computeRelsC14NDigest(contents)
		if err != nil {
			return err
		}
		m.rootRelsC14NDigest = c14nDigest
		return m.addFileNoDigest(relPath(parent), contents)
	}
	return m.addFile(relPath(parent), contents)
}

// newRelsNoDigest creates a rels file without adding it to the signature manifest.
// Used for HLKX where origin rels are not signed.
func (m *mangler) newRelsNoDigest(parent, child, relType string) error {
	var rels oxfRelationships
	rels.Append(child, relType)
	contents, err := rels.Marshal()
	if err != nil {
		return err
	}
	return m.addFileNoDigest(relPath(parent), contents)
}

func (m *mangler) addOrigin() error {
	// HLKX: origin file is NOT part of the signature manifest
	return m.addFileNoDigest(originPath, nil)
}

func (m *mangler) addCerts(cert *certloader.Certificate, sigName string) error {
	// NB: neither the certs nor the rels file are part of the signature, so
	// bypass m.digests and just call NewFile directly.
	// HLKX embeds only the leaf certificate (not the full chain).
	var rels oxfRelationships
	leaf := cert.Leaf
	certpath := path.Join(xmlCertPath, calcCertFileName(leaf)+".cer")
	if err := m.m.NewFile(certpath, leaf.Raw); err != nil {
		return err
	}
	rels.Append(certpath, certType)
	contents, err := rels.Marshal()
	if err != nil {
		return err
	}
	return m.m.NewFile(relPath(sigName), contents)
}
