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
	"encoding/xml"
	"io"
	"path"
	"sort"
	"strings"

	"github.com/mind-security/relic/v8/lib/signappx"
	"github.com/mind-security/relic/v8/lib/zipslicer"
)

type mangler struct {
	m           *zipslicer.Mangler
	digests     map[string][]byte
	ctypes      *signappx.ContentTypes
	hash        crypto.Hash
	rootRels    *oxfRelationships // pre-existing root relationships to preserve
	rootRelsRef *relsTransformRef // RelationshipTransform digest for _rels/.rels
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
// Attributes are emitted in C14N alphabetical order: Id, Target, TargetMode, Type.
func buildRelsCanonical(rels []oxfRelationship) ([]byte, error) {
	type xmlRelationship struct {
		Id         string `xml:"Id,attr"`
		Target     string `xml:"Target,attr"`
		TargetMode string `xml:"TargetMode,attr"`
		Type       string `xml:"Type,attr"`
	}
	type xmlRelationships struct {
		XMLName      xml.Name `xml:"Relationships"`
		XMLNS        string   `xml:"xmlns,attr"`
		Relationship []xmlRelationship
	}
	xRels := xmlRelationships{XMLNS: relsNS}
	for _, rel := range rels {
		xRels.Relationship = append(xRels.Relationship, xmlRelationship{
			Id:         rel.Id,
			Target:     rel.Target,
			TargetMode: "Internal",
			Type:       rel.Type,
		})
	}
	return xml.Marshal(xRels)
}
