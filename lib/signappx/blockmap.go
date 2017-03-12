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

package signappx

import (
	"archive/zip"
	"crypto"
	"crypto/hmac"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"
)

var hashAlgs = map[crypto.Hash]string{
	crypto.SHA256: "http://www.w3.org/2001/04/xmlenc#sha256",
	crypto.SHA384: "http://www.w3.org/2001/04/xmldsig-more#sha384",
	crypto.SHA512: "http://www.w3.org/2001/04/xmlenc#sha512",
}

var noHashFiles = map[string]bool{
	appxSignature:     true,
	appxCodeIntegrity: true,
	appxContentTypes:  true,
	appxBlockMap:      true,
}

type blockMap struct {
	XmlName    xml.Name `xml:"http://schemas.microsoft.com/appx/2010/blockmap BlockMap"`
	HashMethod string   `xml:",attr"`
	File       []blockFile
}

type blockFile struct {
	Name    string `xml:",attr"`
	Size    uint64 `xml:",attr"`
	LfhSize int    `xml:",attr"`
	Block   []block
}

type block struct {
	Hash string `xml:",attr"`
	Size uint64 `xml:",attr"`
}

func verifyBlockMap(inz *zip.Reader, files zipFiles, skipDigests bool) error {
	isBundle := files[bundleManifestFile] != nil
	zf := files[appxBlockMap]
	if zf == nil {
		return errors.New("missing block map")
	}
	blob, err := readZipFile(zf)
	if err != nil {
		return err
	}
	var bm blockMap
	if err := xml.Unmarshal(blob, &bm); err != nil {
		return fmt.Errorf("error parsing block map: %s", err)
	}
	var hash crypto.Hash
	for hash2, alg := range hashAlgs {
		if alg == bm.HashMethod {
			hash = hash2
			break
		}
	}
	if hash == 0 {
		return errors.New("unsupported hash in block map")
	}
	bmfiles := bm.File
	for _, zf := range inz.File {
		if noHashFiles[zf.Name] || (isBundle && strings.HasSuffix(zf.Name, ".appx")) {
			continue
		}
		if len(bmfiles) == 0 {
			return fmt.Errorf("blockmap: unhashed zip file %s", zf.Name)
		}
		bmf := bmfiles[0]
		bmfiles = bmfiles[1:]
		name := strings.Replace(zf.Name, "/", "\\", -1)
		lfhSize := 30 + len(zf.Name) + len(zf.Extra) // size of zip local file header
		if bmf.Name != name || bmf.Size != zf.UncompressedSize64 || bmf.LfhSize != lfhSize {
			return errors.New("blockmap: file mismatch")
		}
		if len(bmf.Block) != int((zf.UncompressedSize64+65535)/65536) {
			return errors.New("blockmap: file mismatch")
		}
		if skipDigests {
			continue
		}
		r, err := zf.Open()
		if err != nil {
			return err
		}
		remaining := zf.UncompressedSize64
		for i, block := range bmf.Block {
			count := remaining
			if count > 65536 {
				count = 65536
			}
			remaining -= count
			d := hash.New()
			if _, err := io.CopyN(d, r, int64(count)); err != nil {
				return err
			}
			calc := d.Sum(nil)
			expected, err := base64.StdEncoding.DecodeString(block.Hash)
			if err != nil {
				return fmt.Errorf("blockmap: %s", err)
			}
			if !hmac.Equal(calc, expected) {
				return fmt.Errorf("blockmap: digest mismatch for %s block %d: calculated %x != found %x", name, i, calc, expected)
			}
		}
		if err := r.Close(); err != nil {
			return err
		}
		if remaining > 0 {
			return errors.New("blockmap: file mismatch")
		}
	}
	return nil
}
