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
	"crypto"
	"crypto/hmac"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/sassoftware/relic/v7/lib/zipslicer"
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

	Hash            crypto.Hash `xml:"-"`
	unverifiedSizes bool
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
		return fmt.Errorf("error parsing block map: %w", err)
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
		name := zipToDos(zf.Name)
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
				return fmt.Errorf("blockmap: %w", err)
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

// Copy compressed sizes from the old blockmap since I can't figure out how
// they come up with the numbers and the thing won't install if they're
// wrong...
func (b *blockMap) CopySizes(blob []byte) error {
	var orig blockMap
	if err := xml.Unmarshal(blob, &orig); err != nil {
		return fmt.Errorf("error parsing block map: %w", err)
	}
	for i, oldf := range orig.File {
		zipName := dosToZip(oldf.Name)
		if zipName == appxManifest || zipName == bundleManifestFile {
			// The only file that gets changed by us. It's stored with no
			// compression to avoid screwing up the sizes.
			continue
		} else if i >= len(b.File) {
			return errors.New("old block map has too many files")
		}
		newf := &b.File[i]
		if newf.Name != oldf.Name {
			return fmt.Errorf("old block map doesn't match new: %s", oldf.Name)
		}
		for j, oldblock := range oldf.Block {
			newf.Block[j].Size = oldblock.Size
		}
	}
	b.unverifiedSizes = false
	return nil
}

func (b *blockMap) AddFile(f *zipslicer.File, raw, cooked io.Writer) error {
	bmf := blockFile{Name: zipToDos(f.Name)}
	lfh, err := f.GetLocalHeader()
	if err != nil {
		return fmt.Errorf("hashing zip metadata: %w", err)
	}
	bmf.LfhSize = len(lfh)
	if raw != nil {
		if _, err := raw.Write(lfh); err != nil {
			return err
		}
	}
	rc, err := f.OpenAndTeeRaw(raw)
	if err != nil {
		return fmt.Errorf("hashing zip metadata: %w", err)
	}
	// Copy 64K of uncompressed data at a time, adding block elements as we go
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
			bmf.Block = append(bmf.Block, block{Hash: hash})
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
		return fmt.Errorf("hashing zip metadata: %w", err)
	}
	if raw != nil {
		if _, err := raw.Write(dd); err != nil {
			return err
		}
	}
	if !(noHashFiles[f.Name] || strings.HasSuffix(f.Name, ".appx")) {
		if f.Method != zip.Store {
			b.unverifiedSizes = true
		}
		b.File = append(b.File, bmf)
	}
	return nil
}

func (b *blockMap) Marshal() ([]byte, error) {
	if b.unverifiedSizes {
		return nil, errors.New("found compressed files not already in blockmap")
	}
	return marshalXML(b, false)
}

func zipToDos(name string) string {
	return strings.ReplaceAll(name, "/", "\\")
}

func dosToZip(name string) string {
	return strings.ReplaceAll(name, "\\", "/")
}
