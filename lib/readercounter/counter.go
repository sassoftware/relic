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

package readercounter

import "io"

// Wraps a Reader and counts how many bytes are read from it
type ReaderCounter struct {
	R io.Reader // underlying Reader
	N int64     // number of bytes read
}

func New(r io.Reader) *ReaderCounter {
	return &ReaderCounter{R: r}
}

func (c *ReaderCounter) Read(d []byte) (int, error) {
	n, err := c.R.Read(d)
	c.N += int64(n)
	return n, err
}
