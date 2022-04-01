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

package vsix

import (
	"crypto"
	"io"
	"path"
	"strings"

	"github.com/sassoftware/relic/v7/lib/signappx"
	"github.com/sassoftware/relic/v7/lib/zipslicer"
)

type mangler struct {
	m       *zipslicer.Mangler
	digests map[string][]byte
	ctypes  *signappx.ContentTypes
	hash    crypto.Hash
}

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
	case ".rels", ".psdsxs", ".psdor":
		return false
	}
	switch {
	case strings.HasPrefix(fp, digSigPath+"/"):
		return false
	}
	return true
}
