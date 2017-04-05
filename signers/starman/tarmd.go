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

package starman

import (
	"archive/tar"
	"crypto"
	"crypto/hmac"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

type TarMD struct {
	Name             string  `json:"name"`
	Arch             string  `json:"arch"`
	Version          Version `json:"version"`
	Files            []File  `json:"files"`
	FileCheckSumType string  `json:"file_checksum_type"`
}

type Version struct {
	Epoch   string `json:"epoch"`
	Version string `json:"version"`
	Release string `json:"release"`
}

type File struct {
	Name      string `json:"name"`
	Size      int64  `json:"size"`
	Mode      int    `json:"mode"`
	Mtime     int    `json:"mtime"`
	Digest    string `json:"digest"`
	Flags     int    `json:"flags"`
	UserName  string `json:"username"`
	GroupName string `json:"groupname"`
}

var hashMap = map[string]crypto.Hash{
	"md5":    crypto.MD5,
	"sha1":   crypto.SHA1,
	"sha224": crypto.SHA224,
	"sha256": crypto.SHA256,
	"sha384": crypto.SHA384,
	"sha512": crypto.SHA512,
}

func (i *starmanInfo) verifyFiles(tr *tar.Reader) error {
	if err := json.Unmarshal(i.mdblob, &i.md); err != nil {
		return err
	}
	md := &i.md
	hash := hashMap[md.FileCheckSumType]
	if !hash.Available() {
		return fmt.Errorf("unknown digest type %s", md.FileCheckSumType)
	} else if hash < crypto.SHA224 {
		return fmt.Errorf("digest type %s is too weak", md.FileCheckSumType)
	}
	filemap := make(map[string]*File, len(md.Files))
	for i := range md.Files {
		filemd := &md.Files[i]
		filemap[filemd.Name] = filemd
	}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}
		name := strings.TrimLeft(hdr.Name, ".")
		filemd := filemap[name]
		if filemd == nil {
			return fmt.Errorf("file %s is missing from metadata", name)
		}
		delete(filemap, name)

		if hdr.Typeflag == tar.TypeLink {
			// has a digest but no contents
			continue
		} else if filemd.Digest != "" {
			d := hash.New()
			if hdr.FileInfo().Mode()&os.ModeSymlink != 0 {
				d.Write([]byte(hdr.Linkname))
			} else {
				if _, err := io.Copy(d, tr); err != nil {
					return err
				}
			}
			sum := d.Sum(nil)
			expect, err := hex.DecodeString(filemd.Digest)
			if err != nil {
				return err
			}
			if !hmac.Equal(expect, sum) {
				return fmt.Errorf("digest mismatch for %s: given %x, calculated %x", expect, sum)
			}
		} else {
			switch hdr.FileInfo().Mode() & os.ModeType {
			case 0, os.ModeSymlink:
				return fmt.Errorf("file %s has no digest", name)
			}
		}
	}
	for k := range filemap {
		return fmt.Errorf("file %s missing from tar", k)
	}
	return nil
}
