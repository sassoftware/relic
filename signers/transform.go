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
// into the original file.

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/atomicfile"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/binpatch"
)

type Transformer interface {
	GetReader() (stream io.Reader, size int64, err error)
	Apply(dest, mimetype string, result io.Reader) error
}

func (s *Signer) GetTransform(f *os.File, opts SignOpts) (Transformer, error) {
	if s != nil && s.Transform != nil {
		return s.Transform(f, opts)
	}
	return fileProducer{f}, nil
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

func (p fileProducer) Apply(dest, mimetype string, result io.Reader) error {
	if mimetype == binpatch.MimeType {
		blob, err := ioutil.ReadAll(result)
		if err != nil {
			return err
		}
		patch, err := binpatch.Load(blob)
		if err != nil {
			return err
		}
		return patch.Apply(p.f, dest)
	} else {
		f, err := atomicfile.WriteAny(dest)
		if err != nil {
			return err
		}
		if _, err := io.Copy(f, result); err != nil {
			return err
		}
		return f.Commit()
	}
}
