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

package xmldsig

import (
	"sort"

	"github.com/beevik/etree"
)

// Canonicalize a document starting from the given element and return the
// serialized bytes. Implements something vaguely like xml-exc-c14n. Namespaces
// declared in parent nodes are pulled in, and namespaces not used in the
// element where they are declared are pushed further down to the elements that
// use them.
//
// This is not a standards-conforming implementation. Use at your own peril.
func SerializeCanonical(oldroot *etree.Element) ([]byte, error) {
	// make a deep copy before mangling things
	root := oldroot.Copy()
	// remake the document without any xml declarations etc.
	doc := etree.NewDocument()
	doc.SetRoot(root)
	doc.WriteSettings.CanonicalEndTags = true
	doc.WriteSettings.CanonicalText = true
	doc.WriteSettings.CanonicalAttrVal = true
	pullDown(oldroot, root)
	walkAttributes(root)
	return doc.WriteToBytes()
}

// if the attribute is a namespace declaration then return the namespace
func getDecl(attr etree.Attr) (string, bool) {
	if attr.Space == "" && attr.Key == "xmlns" {
		return "", true
	} else if attr.Space == "xmlns" {
		return attr.Key, true
	} else {
		return "", false
	}
}

// attribute name for declaring the given namespace
func putDecl(space string) string {
	if space == "" {
		return "xmlns"
	}
	return "xmlns:" + space
}

func walkAttributes(elem *etree.Element) {
	// remove unused spaces and push ones this element doesn't use down to child elements
	for i := 0; i < len(elem.Attr); {
		attr := elem.Attr[i]
		if space, isDecl := getDecl(attr); isDecl && !usesSpace(elem, space) {
			pushDown(elem, elem, space, putDecl(space), attr.Value)
			elem.Attr = append(elem.Attr[:i], elem.Attr[i+1:]...)
			continue
		}
		i++
	}
	sort.Slice(elem.Attr, func(i, j int) bool {
		x := elem.Attr[i]
		y := elem.Attr[j]
		// default namespace node sorts first
		if x.Space == "" && x.Key == "xmlns" {
			return true
		} else if y.Space == "" && y.Key == "xmlns" {
			return false
		}
		// then all other namespace nodes
		if x.Space == "xmlns" && y.Space != "xmlns" {
			return true
		} else if y.Space == "xmlns" && x.Space != "xmlns" {
			return false
		}
		// then order by namespace and finally by key
		if x.Space != y.Space {
			return x.Space < y.Space
		}
		return x.Key < y.Key
	})
	for i := 0; i < len(elem.Child); {
		token := elem.Child[i]
		switch t := token.(type) {
		case *etree.Element:
			walkAttributes(t)
		case *etree.CharData:
			// keep
		default:
			// remove
			elem.Child = append(elem.Child[:i], elem.Child[i+1:]...)
			continue
		}
		i++
	}
}

// does this element or its attributes reference the given namespace?
func usesSpace(elem *etree.Element, space string) bool {
	if elem.Space == space {
		return true
	} else if space == "" {
		// if the element doesn't use the default namespace, then neither do the attributes
		return false
	}
	for _, attr := range elem.Attr {
		if attr.Space == space {
			return true
		}
	}
	return false
}

// if the root element used to be the child of another element, pull down
// namespaces that were declared in its ancestors
func pullDown(oldroot, newroot *etree.Element) {
	spaces := make(map[string]string)
	for p := oldroot.Parent(); p != nil; p = p.Parent() {
		for _, attr := range p.Attr {
			space, isDecl := getDecl(attr)
			if !isDecl {
				continue
			}
			if spaces[space] != "" {
				continue
			}
			spaces[space] = attr.Value
		}
	}
	for space, value := range spaces {
		pushDown(nil, newroot, space, putDecl(space), value)
	}
}

// add a namespace to child elements that need it
func pushDown(top, elem *etree.Element, space, key, value string) {
	if elem != top && elem.SelectAttr(key) != nil {
		// redeclared here already
		return
	} else if usesSpace(elem, space) {
		// used here, declare it here
		elem.CreateAttr(key, value)
	} else {
		// recurse further
		for _, elem := range elem.ChildElements() {
			pushDown(top, elem, space, key, value)
		}
	}
}
