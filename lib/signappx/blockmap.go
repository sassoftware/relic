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

	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/zipslicer"
)

const blockMapSize = 64 * 1024

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
	XMLName    xml.Name `xml:"http://schemas.microsoft.com/appx/2010/blockmap BlockMap"`
	HashMethod string   `xml:",attr"`
	File       []blockFile

	Hash crypto.Hash `xml:"-"`
}

type blockFile struct {
	Name    string `xml:",attr"`
	Size    uint64 `xml:",attr"`
	LfhSize int    `xml:",attr"`
	Block   []block
}

type block struct {
	Hash string `xml:",attr"`
	Size uint64 `xml:",attr,omitempty"`
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
	bm.Hash = hash
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
		if bmf.Name != name {
			return fmt.Errorf("blockmap: file mismatch: %s != %s", bmf.Name, name)
		} else if bmf.Size != zf.UncompressedSize64 {
			return fmt.Errorf("blockmap: file mismatch: %s: size %d != %d", name, bmf.Size, zf.UncompressedSize64)
		}
		if len(bmf.Block) != int((zf.UncompressedSize64+blockMapSize-1)/blockMapSize) {
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
			if count > blockMapSize {
				count = blockMapSize
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

func (b *blockMap) SetHash(hash crypto.Hash) error {
	alg := hashAlgs[hash]
	if alg == "" {
		return errors.New("unsupported hash algorithm")
	}
	b.HashMethod = alg
	b.Hash = hash
	return nil
}

func (b *blockMap) AddFile(f *zipslicer.File, raw, cooked io.Writer) error {
	var bmf blockFile
	bmf.Name = strings.Replace(f.Name, "/", "\\", -1)
	lfh, err := f.GetLocalHeader()
	if err != nil {
		return fmt.Errorf("hashing zip metadata: %s", err)
	}
	bmf.LfhSize = len(lfh)
	if raw != nil {
		raw.Write(lfh)
	}
	rc, err := f.OpenAndTeeRaw(raw)
	if err != nil {
		return fmt.Errorf("hashing zip metadata: %s", err)
	}
	// Copy 64K of uncompressed data at a time, adding block elements as we go
	var pos int64
	for {
		d := b.Hash.New()
		w := io.Writer(d)
		if cooked != nil {
			w = io.MultiWriter(d, cooked)
		}
		n, err := io.CopyN(w, rc, blockMapSize)
		if n > 0 {
			bmf.Size += uint64(n)
			hash := base64.StdEncoding.EncodeToString(d.Sum(nil))
			var size uint64
			if f.Method != zip.Store {
				p2 := rc.Tell()
				size = uint64(p2 - pos)
				pos = p2
			}
			bmf.Block = append(bmf.Block, block{Hash: hash, Size: size})
		}
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}
	}
	if err := rc.Close(); err != nil {
		return err
	}
	dd, err := f.GetDataDescriptor()
	if err != nil {
		return fmt.Errorf("hashing zip metadata: %s", err)
	}
	if raw != nil {
		raw.Write(dd)
	}
	if !(noHashFiles[f.Name] || strings.HasSuffix(f.Name, ".appx")) {
		b.File = append(b.File, bmf)
	}
	return nil
}

func (b *blockMap) Marshal() ([]byte, error) {
	return marshalXml(b)
}
