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

package authenticode

import (
	"archive/tar"
	"bytes"
	"crypto"
	"fmt"
	"io"
	"io/ioutil"

	"github.com/sassoftware/relic/v7/lib/comdoc"
)

const (
	msiTarExMeta     = "__exmeta"
	msiTarStorageUID = "__storage_uid"
)

// Convert MSI to a tar archive in a form that can be digested and signed as a
// stream
func MsiToTar(cdf *comdoc.ComDoc, w io.Writer) error {
	tw := tar.NewWriter(w)
	// First write the metadata that is needed for an extended signature
	var buf bytes.Buffer
	if err := prehashMsiDir(cdf, cdf.RootStorage(), &buf); err != nil {
		return err
	}
	if err := tarAddFile(tw, msiTarExMeta, buf.Bytes()); err != nil {
		return err
	}
	// Now all of the files in the same order they would get digested in
	if err := msiToTarDir(cdf, tw, cdf.RootStorage(), ""); err != nil {
		return err
	}
	return tw.Close()
}

// Digset a tarball produced by MsiToTar
func DigestMsiTar(r io.Reader, hash crypto.Hash, extended bool) ([]byte, error) {
	tr := tar.NewReader(r)
	d := hash.New()
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
		if hdr.Name == msiTarExMeta {
			if !extended {
				continue
			}
			exmeta, err := ioutil.ReadAll(tr)
			if err != nil {
				return nil, err
			}
			d2 := hash.New()
			d2.Write(exmeta)
			prehash := d2.Sum(nil)
			d.Write(prehash)
		} else if hdr.Name == msiDigitalSignature || hdr.Name == msiDigitalSignatureEx {
			continue
		}
		if _, err := io.Copy(d, tr); err != nil {
			return nil, err
		}
	}
	return d.Sum(nil), nil
}

// Add a file with contents blob to an open tar.Writer
func tarAddFile(tw *tar.Writer, name string, contents []byte) error {
	hdr := &tar.Header{Name: name, Mode: 0644, Size: int64(len(contents))}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err := tw.Write(contents)
	return err
}

// Recursively copy streams from a MSI directory (storage) to a tar.Writer
func msiToTarDir(cdf *comdoc.ComDoc, tw *tar.Writer, parent *comdoc.DirEnt, path string) error {
	files, err := cdf.ListDir(parent)
	if err != nil {
		if path == "" {
			return fmt.Errorf("listing root storage: %w", err)
		}
		return fmt.Errorf("listing storage %q: %w", path, err)
	}
	sortMsiFiles(files)
	for _, item := range files {
		itemPath := path + msiDecodeName(item.Name())
		switch item.Type {
		case comdoc.DirStream:
			r, err := cdf.ReadStream(item)
			if err != nil {
				return fmt.Errorf("reading MSI stream %q: %w", itemPath, err)
			}
			hdr := &tar.Header{
				Name: itemPath,
				Mode: 0644,
				Size: int64(item.StreamSize),
			}
			if err := tw.WriteHeader(hdr); err != nil {
				return err
			}
			if _, err := io.Copy(tw, r); err != nil {
				return fmt.Errorf("transforming MSI stream %q: %w", itemPath, err)
			}
		case comdoc.DirStorage:
			if err := msiToTarDir(cdf, tw, item, itemPath+"/"); err != nil {
				return err
			}
		}
	}
	// The UID of each storage gets hashed after its contents so include that, too
	return tarAddFile(tw, path+msiTarStorageUID, parent.UID[:])
}
