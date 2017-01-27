/*
 * Copyright (c) SAS Institute Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package signjar

import (
	"bytes"
	"crypto"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"gerrit-pdt.unx.sas.com/tools/relic.git/config"
)

// See https://docs.oracle.com/javase/8/docs/technotes/guides/jar/jar.html#JAR_Manifest

type FilesMap struct {
	Main  http.Header
	Order []string
	Files map[string]http.Header
}

func ParseManifest(manifest []byte) (files *FilesMap, err error) {
	manifest = bytes.Replace(manifest, []byte("\r\n"), []byte{'\n'}, -1)
	sections := bytes.Split(manifest, []byte("\n\n"))
	files = &FilesMap{
		Order: make([]string, 0, len(sections)-1),
		Files: make(map[string]http.Header, len(sections)-1),
	}
	for i, section := range sections {
		if i > 0 && len(section) == 0 {
			continue
		}
		section = bytes.Replace(section, []byte("\n "), []byte{}, -1)
		keys := bytes.Split(section, []byte{'\n'})
		hdr := make(http.Header)
		for _, line := range keys {
			if len(line) == 0 {
				continue
			}
			idx := bytes.IndexRune(line, ':')
			if idx < 0 {
				return nil, errors.New("jar manifest is malformed")
			}
			key := strings.TrimSpace(string(line[:idx]))
			value := strings.TrimSpace(string(line[idx+1:]))
			hdr.Set(key, value)
		}
		if i == 0 {
			files.Main = hdr
		} else {
			name := hdr.Get("Name")
			if name == "" {
				return nil, errors.New("manifest has section with no \"Name\" attribute")
			}
			files.Order = append(files.Order, name)
			files.Files[name] = hdr
		}
	}
	return files, nil
}

func DumpManifest(files *FilesMap) []byte {
	var out bytes.Buffer
	writeSection(&out, files.Main, "Manifest-Version")
	for _, name := range files.Order {
		section := files.Files[name]
		if section != nil {
			writeSection(&out, section, "Name")
		}
	}
	return out.Bytes()
}

// Transform a MANIFEST.MF into a *.SF by digesting each section with the
// specified hash
func DigestManifest(manifest []byte, hash crypto.Hash) ([]byte, error) {
	hashName := hashNames[hash]
	if hashName == "" {
		return nil, errors.New("unsupported hash type")
	}
	b64 := base64.StdEncoding
	digestAll := hash.New()
	digestAll.Write(manifest)
	hashManifest := digestAll.Sum(nil)
	var hashMain []byte

	var files bytes.Buffer
	mainSection := true
	for len(manifest) != 0 {
		digestSection := hash.New()
		copyingName := false
		sawName := false
		for len(manifest) != 0 {
			i := bytes.IndexByte(manifest, '\n')
			if i < 0 {
				return nil, errors.New("trailing bytes after last newline")
			}
			i++
			line := manifest[:i]
			manifest = manifest[i:]
			digestSection.Write(line)
			linestr := string(line)
			if linestr == "\r\n" || linestr == "\n" {
				break
			} else if !mainSection && strings.HasPrefix(strings.ToLower(linestr), "name:") {
				copyingName = true
				sawName = true
				files.Write(line)
			} else if len(linestr) != 0 && linestr[0] != ' ' {
				copyingName = false
			} else if copyingName {
				files.Write(line)
			}
		}
		if mainSection {
			mainSection = false
			hashMain = digestSection.Sum(nil)
		} else {
			if !sawName {
				return nil, errors.New("File section was missing Name attribute")
			}
			writeAttribute(&files, hashName+"-Digest", b64.EncodeToString(digestSection.Sum(nil)))
			files.WriteString("\r\n")
		}
	}

	var output bytes.Buffer
	writeAttribute(&output, "Signature-Version", "1.0")
	writeAttribute(&output, hashName+"-Digest-Manifest-Main-Attributes", b64.EncodeToString(hashMain))
	writeAttribute(&output, hashName+"-Digest-Manifest", b64.EncodeToString(hashManifest))
	writeAttribute(&output, "Created-By", fmt.Sprintf("%s (%s)", config.UserAgent, config.Author))
	output.WriteString("\r\n")
	output.Write(files.Bytes())
	return output.Bytes(), nil
}

const maxLineLength = 70

// Write a key-value pair, wrapping long lines as necessary
func writeAttribute(out io.Writer, key, value string) {
	line := []byte(fmt.Sprintf("%s: %s", key, value))
	for i := 0; i < len(line); i += maxLineLength {
		j := i + maxLineLength
		if j > len(line) {
			j = len(line)
		}
		if i != 0 {
			out.Write([]byte{' '})
		}
		out.Write(line[i:j])
		out.Write([]byte("\r\n"))
	}
}

func writeSection(out io.Writer, hdr http.Header, first string) {
	value := hdr.Get(first)
	if value != "" {
		writeAttribute(out, first, value)
	}
	for key, values := range hdr {
		if key == first {
			continue
		}
		for _, value := range values {
			writeAttribute(out, key, value)
		}
	}
	out.Write([]byte("\r\n"))
}

var hashNames = map[crypto.Hash]string{
	crypto.MD5:    "MD5",
	crypto.SHA1:   "SHA1",
	crypto.SHA224: "SHA-224",
	crypto.SHA256: "SHA-256",
	crypto.SHA384: "SHA-384",
	crypto.SHA512: "SHA-512",
}
