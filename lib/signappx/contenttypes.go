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
	"encoding/xml"
	"path"
	"sort"
)

var defaultExtensions = map[string]string{
	"dll":  "application/x-msdownload",
	"exe":  "application/x-msdownload",
	"png":  "image/png",
	"xml":  "application/vnd.ms-appx.manifest+xml",
	"appx": "application/vnd.ms-appx",
}

var defaultOverrides = map[string]string{
	"/AppxBlockMap.xml":               "application/vnd.ms-appx.blockmap+xml",
	"/AppxSignature.p7x":              "application/vnd.ms-appx.signature",
	"/AppxMetadata/CodeIntegrity.cat": "application/vnd.ms-pkiseccat",
}

const (
	octetStreamType    = "application/octet-stream"
	bundleManifestType = "application/vnd.ms-appx.bundlemanifest+xml"
)

type ContentTypes struct {
	ByExt      map[string]string
	ByOverride map[string]string
}

type xmlContentTypes struct {
	XMLName  xml.Name `xml:"http://schemas.openxmlformats.org/package/2006/content-types Types"`
	Default  []contentTypeDefault
	Override []contentTypeOverride
}

type contentTypeDefault struct {
	Extension   string `xml:",attr"`
	ContentType string `xml:",attr"`
}

type contentTypeOverride struct {
	PartName    string `xml:",attr"`
	ContentType string `xml:",attr"`
}

func NewContentTypes() *ContentTypes {
	return &ContentTypes{
		ByExt:      make(map[string]string),
		ByOverride: make(map[string]string),
	}
}

func (c *ContentTypes) Parse(blob []byte) error {
	var xct xmlContentTypes
	if err := xml.Unmarshal(blob, &xct); err != nil {
		return err
	}
	for _, def := range xct.Default {
		c.ByExt[def.Extension] = def.ContentType
	}
	for _, ovr := range xct.Override {
		c.ByOverride[ovr.PartName] = ovr.ContentType
	}
	return nil
}

func (c *ContentTypes) Add(name string) {
	if name == bundleManifestFile {
		c.ByExt["xml"] = bundleManifestType
		return
	}
	oname := "/" + name
	if ctype := defaultOverrides[oname]; ctype != "" {
		c.ByOverride[oname] = ctype
		return
	} else if ctype := c.ByOverride[oname]; ctype != "" {
		return
	}
	ext := path.Ext(path.Base(name))
	if ext[0] == '.' {
		ext = ext[1:]
		if ctype := defaultExtensions[ext]; ctype != "" {
			c.ByExt[ext] = ctype
		} else if ctype := c.ByExt[ext]; ctype != "" {
			return
		} else {
			c.ByExt[ext] = octetStreamType
		}
	} else {
		c.ByOverride[oname] = octetStreamType
	}
}

func (c *ContentTypes) Find(name string) string {
	oname := "/" + name
	if ctype := c.ByOverride[oname]; ctype != "" {
		return ctype
	}
	ext := path.Ext(path.Base(name))
	if ext[0] == '.' {
		if ctype := c.ByExt[ext[1:]]; ctype != "" {
			return ctype
		}
	}
	return ""
}

func (c *ContentTypes) Marshal() ([]byte, error) {
	var xct xmlContentTypes
	extnames := make([]string, 0, len(c.ByExt))
	for name := range c.ByExt {
		extnames = append(extnames, name)
	}
	sort.Strings(extnames)
	for _, name := range extnames {
		xct.Default = append(xct.Default, contentTypeDefault{
			Extension:   name,
			ContentType: c.ByExt[name],
		})
	}
	ovrnames := make([]string, 0, len(c.ByOverride))
	for name := range c.ByOverride {
		ovrnames = append(ovrnames, name)
	}
	sort.Strings(ovrnames)
	for _, name := range ovrnames {
		xct.Override = append(xct.Override, contentTypeOverride{
			PartName:    name,
			ContentType: c.ByOverride[name],
		})
	}
	return marshalXML(xct, true)
}
