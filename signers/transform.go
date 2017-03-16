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

package signers

// Some package types can't be signed as a stream as-is, so we transform them
// into something else (a tarball) and upload that to the server. The server
// signs the tar, returns the signature blob, and the client inserts the blob
// into the original file. This mechanism can also be used for cases that don't
// need a transform on the upload but do need special processing on the result
// side. A default implementation that handles patching, copying, and
// overwriting is provided.

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/atomicfile"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/binpatch"
)

type Transformer interface {
	// Return a stream that will be uploaded to a remote server. This may be
	// called multiple times in case of failover. If the size is not known then
	// return -1
	GetReader() (stream io.Reader, size int64, err error)
	// Apply a HTTP response to the named destination file
	Apply(dest, mimetype string, result io.Reader) error
}

// Return the transform for the given module if it has one, otherwise return
// the default transform.
func (s *Signer) GetTransform(f *os.File, opts SignOpts) (Transformer, error) {
	if s != nil && s.Transform != nil {
		return s.Transform(f, opts)
	}
	return fileProducer{f}, nil
}

func DefaultTransform(f *os.File) Transformer {
	return fileProducer{f}
}

// Dummy implementation that sends the original file as a request, and
// either applies a binary patch or overwrites the whole file depending on the
// MIME type.

type fileProducer struct {
	f *os.File
}

func (p fileProducer) GetReader() (io.Reader, int64, error) {
	size, err := p.f.Seek(0, io.SeekEnd)
	if err != nil {
		return nil, -1, fmt.Errorf("failed to seek input file: %s", err)
	}
	p.f.Seek(0, io.SeekStart)
	return p.f, size, nil
}

// If the response is a binpatch, apply it. Otherwise overwrite the destination
// file with the response
func (p fileProducer) Apply(dest, mimetype string, result io.Reader) error {
	if mimetype == binpatch.MimeType {
		return ApplyBinPatch(p.f, dest, result)
	} else {
		f, err := atomicfile.WriteAny(dest)
		if err != nil {
			return err
		}
		if _, err := io.Copy(f, result); err != nil {
			return err
		}
		p.f.Close()
		return f.Commit()
	}
}

func ApplyBinPatch(src *os.File, dest string, result io.Reader) error {
	blob, err := ioutil.ReadAll(result)
	if err != nil {
		return err
	}
	patch, err := binpatch.Load(blob)
	if err != nil {
		return err
	}
	return patch.Apply(src, dest)
}
