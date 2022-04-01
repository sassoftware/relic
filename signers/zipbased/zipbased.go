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

package zipbased

import (
	"io"
	"os"

	"github.com/sassoftware/relic/v7/lib/zipslicer"
	"github.com/sassoftware/relic/v7/signers"
)

type zipTransformer struct {
	f *os.File
}

func Transform(f *os.File, opts signers.SignOpts) (signers.Transformer, error) {
	return &zipTransformer{f}, nil
}

// Wrap the zip in a tarball with the central directory first so that it can be
// processed as a stream
func (t *zipTransformer) GetReader() (io.Reader, error) {
	r, w := io.Pipe()
	go func() {
		_ = w.CloseWithError(zipslicer.ZipToTar(t.f, w))
	}()
	return r, nil
}

func (t *zipTransformer) Apply(dest, mimeType string, result io.Reader) error {
	return signers.ApplyBinPatch(t.f, dest, result)
}
