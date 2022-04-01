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
	"bytes"
	"crypto"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"strings"
	"time"

	"github.com/sassoftware/relic/v7/lib/authenticode"
	"github.com/sassoftware/relic/v7/lib/zipslicer"
)

type AppxDigest struct {
	Hash             crypto.Hash
	blockMap         blockMap
	manifest         *appxPackage
	bundle           *bundleManifest
	contentTypes     *ContentTypes
	peDigests        []*authenticode.PEDigest
	outz             *zipslicer.Directory
	patchStart       int64
	patchLen         int64
	patchBuf         bytes.Buffer
	mtime            time.Time
	axpc             hash.Hash
	axbm, axct, axci []byte
}

func DigestAppxTar(r io.Reader, hash crypto.Hash, doPageHash bool) (*AppxDigest, error) {
	info := &AppxDigest{
		Hash:         hash,
		axpc:         hash.New(),
		contentTypes: NewContentTypes(),
		outz:         &zipslicer.Directory{},
	}
	if err := info.blockMap.SetHash(hash); err != nil {
		return nil, err
	}
	inz, err := zipslicer.ReadZipTar(r)
	if err != nil {
		return nil, err
	}
	// digest non-signature-related files
copyf:
	for _, f := range inz.File {
		switch f.Name {
		case appxManifest, appxBlockMap, appxContentTypes, appxCodeIntegrity, appxSignature, bundleManifestFile:
			info.patchStart = int64(f.Offset)
			info.patchLen = inz.Size - info.patchStart
			break copyf
		default:
			info.mtime = f.ModTime()
			if err := info.digestFile(f, doPageHash); err != nil {
				return nil, err
			}
			if _, err := info.outz.AddFile(f); err != nil {
				return nil, err
			}
		}
	}
	idx := len(info.outz.File)
	// parse signature-related files for later
	for _, f := range inz.File[idx:] {
		blob, err := readSlicerFile(f)
		if err != nil {
			return nil, err
		}
		switch f.Name {
		case appxManifest:
			manifest, err := parseManifest(blob)
			if err != nil {
				return nil, err
			}
			info.manifest = manifest
		case bundleManifestFile:
			manifest, err := parseBundle(blob)
			if err != nil {
				return nil, err
			}
			info.bundle = manifest
		case appxBlockMap:
			if err := info.blockMap.CopySizes(blob); err != nil {
				return nil, err
			}
		case appxContentTypes:
			if err := info.contentTypes.Parse(blob); err != nil {
				return nil, err
			}
		case appxCodeIntegrity, appxSignature:
			// discard
		default:
			// regular files can't come after files we mangle
			return nil, fmt.Errorf("file %s is out of order", f.Name)
		}
	}
	if info.manifest == nil && info.bundle == nil {
		return nil, errors.New("missing manifest")
	}
	// drain the input to ensure the request is completely read before the response goes out
	if _, err := io.Copy(ioutil.Discard, r); err != nil {
		return nil, err
	}
	return info, nil
}

func readSlicerFile(f *zipslicer.File) ([]byte, error) {
	r, err := f.Open()
	if err != nil {
		return nil, err
	}
	blob, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return blob, r.Close()
}

// 4 different digests need to happen concurrently:
// - AXPC for the raw zip headers and data
// - blockmap 64KiB chunks of cooked data
// - SHA1 and SHA256 digests over PE files for CodeIntegrity.cat
func (i *AppxDigest) digestFile(f *zipslicer.File, doPageHash bool) error {
	var peWriters []io.WriteCloser
	var peResults []<-chan peDigestResult
	var sink io.Writer
	if strings.HasSuffix(f.Name, ".exe") || strings.HasSuffix(f.Name, ".dll") {
		// DigestPE wants a Reader so make a pipe for each one and sink data into the pipes
		peWriters, peResults = setupPeDigests(f.Name, i.Hash, doPageHash)
		defer func() {
			for _, w := range peWriters {
				w.Close()
			}
		}()
		mw := make([]io.Writer, len(peWriters))
		for i, w := range peWriters {
			mw[i] = w
		}
		sink = io.MultiWriter(mw...)
	}
	if err := i.blockMap.AddFile(f, i.axpc, sink); err != nil {
		return err
	}
	if peWriters != nil {
		for _, w := range peWriters {
			w.Close()
		}
		for _, ch := range peResults {
			result := <-ch
			if result.err != nil {
				return result.err
			}
			i.peDigests = append(i.peDigests, result.digest)
		}
	}
	return nil
}

type peDigestResult struct {
	digest *authenticode.PEDigest
	err    error
}

func setupPeDigests(name string, hash crypto.Hash, doPageHash bool) (writers []io.WriteCloser, results []<-chan peDigestResult) {
	w, r := setupPeDigest(name, hash, doPageHash)
	writers = append(writers, w)
	results = append(results, r)
	if hash != crypto.SHA1 {
		// SHA1 for catalog compatibility
		w, r := setupPeDigest(name, crypto.SHA1, doPageHash)
		writers = append(writers, w)
		results = append(results, r)
	}
	return
}

func setupPeDigest(name string, hash crypto.Hash, doPageHash bool) (io.WriteCloser, <-chan peDigestResult) {
	r, w := io.Pipe()
	ch := make(chan peDigestResult, 1)
	go func() {
		digest, err := authenticode.DigestPE(r, hash, doPageHash)
		if err != nil {
			err = fmt.Errorf("failed to update CodeIntegrity catalog for %s: %w", name, err)
		}
		ch <- peDigestResult{digest, err}
		_ = r.CloseWithError(err)
		close(ch)
	}()
	return w, ch
}
