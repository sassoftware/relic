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
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"sort"

	"github.com/mind-security/relic/v8/lib/zipslicer"
)

// opcXMLDecl is the XML declaration for OPC parts.
// OPC spec (ECMA-376 Part 2 §13.2): the standalone attribute must NOT be present.
// We omit the trailing newline so the root element immediately follows, matching
// what Windows OPC tooling produces.
const opcXMLDecl = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"

type xmlTypes struct {
	XMLName  xml.Name          `xml:"http://schemas.openxmlformats.org/package/2006/content-types Types"`
	Default  []xmlTypesDefault `xml:",omitempty"`
	Override []xmlTypesOverride `xml:",omitempty"`
}

type xmlTypesDefault struct {
	Extension   string `xml:",attr"`
	ContentType string `xml:",attr"`
}

type xmlTypesOverride struct {
	PartName    string `xml:",attr"`
	ContentType string `xml:",attr"`
}

func (m *mangler) parseTypes(f *zipslicer.MangleFile) error {
	fc, err := f.Open()
	if err != nil {
		return err
	}
	blob, err := ioutil.ReadAll(fc)
	if err != nil {
		return err
	}
	if err := m.ctypes.Parse(blob); err != nil {
		return fmt.Errorf("parsing %s: %w", f.Name, err)
	}
	return nil
}

func (m *mangler) parseRootRels(f *zipslicer.MangleFile) error {
	fc, err := f.Open()
	if err != nil {
		return err
	}
	blob, err := ioutil.ReadAll(fc)
	if err != nil {
		return err
	}
	rels := new(oxfRelationships)
	if err := xml.Unmarshal(blob, rels); err != nil {
		return fmt.Errorf("parsing %s: %w", f.Name, err)
	}
	m.rootRels = rels
	return nil
}

func (m *mangler) newCtypes() error {
	for ext, ctype := range contentTypes {
		m.ctypes.ByExt[ext] = ctype
	}
	var xct xmlTypes
	extnames := make([]string, 0, len(m.ctypes.ByExt))
	for name := range m.ctypes.ByExt {
		extnames = append(extnames, name)
	}
	sort.Strings(extnames)
	for _, name := range extnames {
		xct.Default = append(xct.Default, xmlTypesDefault{
			Extension:   name,
			ContentType: m.ctypes.ByExt[name],
		})
	}
	ovrnames := make([]string, 0, len(m.ctypes.ByOverride))
	for name := range m.ctypes.ByOverride {
		ovrnames = append(ovrnames, name)
	}
	sort.Strings(ovrnames)
	for _, name := range ovrnames {
		xct.Override = append(xct.Override, xmlTypesOverride{
			PartName:    name,
			ContentType: m.ctypes.ByOverride[name],
		})
	}
	x, err := xml.Marshal(xct)
	if err != nil {
		return err
	}
	// Convert Go's explicit closing tags to self-closing for empty elements,
	// matching the format Windows OPC tooling produces.
	x = bytes.ReplaceAll(x, []byte("></Default>"), []byte("/>"))
	x = bytes.ReplaceAll(x, []byte("></Override>"), []byte("/>"))
	contents := append([]byte(opcXMLDecl), x...)
	return m.m.NewFile(contentTypesPath, contents)
}
