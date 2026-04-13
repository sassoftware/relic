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
	"archive/zip"
	"crypto"
	"io"
	"path"
	"sort"
	"strings"

	"github.com/beevik/etree"
	"github.com/mind-security/relic/v8/lib/signappx"
	"github.com/mind-security/relic/v8/lib/xmldsig"
	"github.com/mind-security/relic/v8/lib/zipslicer"
)

type mangler struct {
	m                  *zipslicer.Mangler
	digests            map[string][]byte
	ctypes             *signappx.ContentTypes
	hash               crypto.Hash
	rootRels           *oxfRelationships // pre-existing root relationships to preserve
	rootRelsRef        *relsTransformRef // RelationshipTransform digest for _rels/.rels
	rootRelsC14NDigest []byte            // plain C14N digest of the written _rels/.rels
}

// relsTransformRef holds the OPC RelationshipTransform digest for _rels/.rels.
type relsTransformRef struct {
	sourceTypes []string // SourceType values for opc:RelationshipsGroupReference
	digest      []byte
}

type zipFiles map[string]*zip.File

func mangleZip(r io.Reader, hash crypto.Hash) (*mangler, error) {
	inz, err := zipslicer.ReadZipTar(r)
	if err != nil {
		return nil, err
	}
	m := &mangler{
		digests: make(map[string][]byte),
		ctypes:  signappx.NewContentTypes(),
		hash:    hash,
	}
	zm, err := inz.Mangle(func(f *zipslicer.MangleFile) error {
		if keepFile(f.Name) {
			sum, err := f.Digest(hash)
			if err != nil {
				return err
			}
			m.digests[f.Name] = sum
			return nil
		} else {
			if f.Name == contentTypesPath {
				if err := m.parseTypes(f); err != nil {
					return err
				}
			}
			if f.Name == relPath("") {
				if err := m.parseRootRels(f); err != nil {
					return err
				}
			}
			f.Delete()
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	m.m = zm
	return m, nil
}

func keepFile(fp string) bool {
	switch fp {
	case rootRelsPath + "/", contentTypesPath:
		return false
	}
	switch path.Ext(fp) {
	case ".rels", ".psdsxs", ".psdsor":
		return false
	}
	switch {
	case strings.HasPrefix(fp, digSigPath+"/"):
		return false
	}
	return true
}

// computeRootRelsRef computes the OPC RelationshipTransform+C14N digest for
// _rels/.rels. Only non-signature relationships from the original file are
// covered by the digest, so adding the sigOriginType relationship to the
// package does not invalidate existing signatures.
func (m *mangler) computeRootRelsRef() error {
	if m.rootRels == nil {
		return nil
	}
	// Collect non-signature relationships, preserving original order for SourceType list.
	var filtered []oxfRelationship
	var sourceTypes []string
	seen := make(map[string]struct{})
	for _, rel := range m.rootRels.Relationship {
		if rel.Type == sigOriginType {
			continue
		}
		filtered = append(filtered, rel)
		if _, ok := seen[rel.Type]; !ok {
			seen[rel.Type] = struct{}{}
			sourceTypes = append(sourceTypes, rel.Type)
		}
	}
	if len(filtered) == 0 {
		return nil
	}
	// Sort relationships by Id for canonical serialization (per OPC spec).
	sort.Slice(filtered, func(i, j int) bool { return filtered[i].Id < filtered[j].Id })
	canonical, err := buildRelsCanonical(filtered)
	if err != nil {
		return err
	}
	d := m.hash.New()
	d.Write(canonical)
	m.rootRelsRef = &relsTransformRef{
		sourceTypes: sourceTypes,
		digest:      d.Sum(nil),
	}
	return nil
}

// buildRelsCanonical produces the canonical XML bytes that result from applying
// the OPC RelationshipTransform followed by C14N to the given relationships.
// Attributes are emitted in C14N alphabetical order: Id, Target, Type.
// buildRelsCanonical produces the canonical XML bytes for the given relationships
// by applying inclusive C14N. This must match what Windows produces when it applies
// the OPC RelationshipTransform (filter by SourceType) + C14N during verification.
func buildRelsCanonical(rels []oxfRelationship) ([]byte, error) {
	root := etree.NewElement("Relationships")
	root.CreateAttr("xmlns", relsNS)
	for _, rel := range rels {
		r := root.CreateElement("Relationship")
		// C14N sorts attributes alphabetically: Id, Target, TargetMode, Type.
		// Windows' OPC RelationshipTransform always writes TargetMode="Internal"
		// for internal relationships even when the source file omits the attribute
		// (alwaysWriteTargetModeAttribute = true in the reference implementation).
		r.CreateAttr("Id", rel.Id)
		r.CreateAttr("Target", rel.Target)
		r.CreateAttr("TargetMode", "Internal")
		r.CreateAttr("Type", rel.Type)
	}
	return xmldsig.SerializeCanonical(root)
}

// computeRelsC14NDigest parses the given rels XML bytes and returns the hash
// of their C14N canonical form. This is used to produce the plain c14n
// manifest Reference that covers the entire _rels/.rels part.
func (m *mangler) computeRelsC14NDigest(xmlBytes []byte) ([]byte, error) {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xmlBytes); err != nil {
		return nil, err
	}
	canon, err := xmldsig.SerializeCanonical(doc.Root())
	if err != nil {
		return nil, err
	}
	d := m.hash.New()
	d.Write(canon)
	return d.Sum(nil), nil
}
