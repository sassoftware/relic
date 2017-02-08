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
	"archive/zip"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"path"
	"strings"
)

// found in the "extra" field of JAR files, not strictly required but it makes
// `file` output actually say JAR
var jarMagic = []byte{0xfe, 0xca, 0, 0}

func DigestJar(jar *zip.Reader, hash crypto.Hash) ([]byte, error) {
	var manifest []byte
	for _, f := range jar.File {
		if f.Name == "META-INF/MANIFEST.MF" {
			r, err := f.Open()
			if err != nil {
				return nil, fmt.Errorf("failed to read JAR manifest: %s", err)
			}
			defer r.Close()
			manifest, err = ioutil.ReadAll(r)
			if err != nil {
				return nil, fmt.Errorf("failed to read JAR manifest: %s", err)
			}
			continue
		}
	}
	if manifest == nil {
		return nil, errors.New("JAR did not contain a manifest")
	}
	files, err := ParseManifest(manifest)
	if err != nil {
		return nil, err
	}

	hashName := hashNames[hash]
	if hashName == "" {
		return nil, errors.New("unsupported hash type")
	}
	hashName += "-Digest"
	b64 := base64.StdEncoding
	changed := false
	for _, f := range jar.File {
		if f.FileInfo().IsDir() {
			continue
		}
		name := strings.ToUpper(f.Name)
		// don't digest the digests
		if strings.HasPrefix(name, "META-INF/") {
			ext := path.Ext(name)
			if ext == ".MF" || ext == ".SF" || ext == ".RSA" || ext == ".DSA" || ext == ".EC" {
				continue
			}
			if strings.HasPrefix(name, "META-INF/SIG-") {
				continue
			}
		}

		// calculate digest over the actual jar contents
		digest := hash.New()
		r, err := f.Open()
		if err != nil {
			return nil, fmt.Errorf("failed to compute digest for JAR file %s: %s", f.Name, err)
		}
		defer r.Close()
		if _, err := io.Copy(digest, r); err != nil {
			return nil, fmt.Errorf("failed to compute digest for JAR file %s: %s", f.Name, err)
		}
		calculated := b64.EncodeToString(digest.Sum(nil))

		// if the manifest has a matching digest, check it. otherwise add to the manifest.
		attrs := files.Files[f.Name]
		if attrs == nil {
			// file is not mentioned in the manifest at all
			files.Files[f.Name] = http.Header{
				"Name":   []string{f.Name},
				hashName: []string{calculated},
			}
			files.Order = append(files.Order, f.Name)
			changed = true
		} else if attrs.Get("Magic") != "" {
			// magic means a special digester is required. hopefully it's already been digested.
		} else if existing := attrs.Get(hashName); existing != "" {
			// manifest has a digest already, check it
			if existing != calculated {
				return nil, fmt.Errorf("%s mismatch for JAR file %s: manifest %s != calculated %s", hashName, f.Name, existing, calculated)
			}
		} else {
			// file in manifest but no matching digest
			attrs.Set(hashName, calculated)
			changed = true
		}
	}
	if changed {
		manifest = DumpManifest(files)
	}
	return manifest, nil
}

type newFile struct {
	Name     string
	Contents []byte
	Extra    []byte
}

func UpdateJar(outw io.Writer, jar *zip.Reader, keyAlias string, pubkey crypto.PublicKey, manifest, sigfile, pkcs []byte) error {
	signame := strings.ToUpper(keyAlias) + ".SF"
	pkcsname := strings.ToUpper(keyAlias)
	switch pubkey.(type) {
	case *rsa.PublicKey:
		pkcsname += ".RSA"
	case *ecdsa.PublicKey:
		pkcsname += ".EC"
	default:
		signame = "SIG-" + signame
		pkcsname = "SIG-" + pkcsname + ".SIG"
	}
	newFiles := []newFile{
		newFile{"META-INF/", nil, jarMagic},
		newFile{"META-INF/MANIFEST.MF", manifest, nil},
		newFile{"META-INF/" + signame, sigfile, nil},
		newFile{"META-INF/" + pkcsname, pkcs, nil},
	}
	// delete old signatures
	for _, f := range jar.File {
		if !strings.HasPrefix(f.Name, "META-INF/") {
			continue
		}
		base := path.Base(f.Name)
		ext := path.Ext(base)
		if base == signame || base == pkcsname {
			continue
		}
		if ext == ".SF" || ext == ".RSA" || ext == ".DSA" || ext == ".EC" || ext == ".SIG" || strings.HasPrefix(base, "SIG-") {
			newFiles = append(newFiles, newFile{f.Name, nil, nil})
		}
	}
	return updateZip(outw, jar, newFiles)
}

func updateZip(outw io.Writer, inz *zip.Reader, newFiles []newFile) error {
	outz := zip.NewWriter(outw)
	defer outz.Close()

	skipFiles := make(map[string]bool, len(newFiles))
	for _, newFile := range newFiles {
		skipFiles[newFile.Name] = true
		if newFile.Contents == nil {
			// just delete, don't update
			continue
		}
		hdr := &zip.FileHeader{
			Name:   newFile.Name,
			Method: zip.Deflate,
			Extra:  newFile.Extra,
		}
		w, err := outz.CreateHeader(hdr)
		if err == nil {
			_, err = w.Write(newFile.Contents)
		}
		if err != nil {
			return err
		}
	}

	for _, f := range inz.File {
		if skipFiles[f.Name] {
			continue
		}
		r, err := f.Open()
		if err != nil {
			return err
		}
		info := f.FileHeader
		w, err := outz.CreateHeader(&info)
		if err != nil {
			return err
		}
		if _, err := io.Copy(w, r); err != nil {
			return err
		}
	}
	return nil
}

func addFile(outz *zip.Writer, name string, contents []byte) error {
	w, err := outz.Create(name)
	if err == nil {
		_, err = w.Write(contents)
	}
	return err
}
