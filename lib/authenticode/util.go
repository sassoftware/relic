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
	"bytes"
	"encoding/binary"
	"io"
)

// read bytes from a stream and return a byte slice, also feeding a hash
func readAndHash(r io.Reader, d io.Writer, n int) ([]byte, error) {
	if n == 0 {
		return nil, nil
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	if d != nil {
		if _, err := d.Write(buf); err != nil {
			return nil, err
		}
	}
	return buf, nil
}

// read from a byte slice into a structure
func binaryReadBytes(buf []byte, val interface{}) error {
	return binary.Read(bytes.NewReader(buf), binary.LittleEndian, val)
}

// pad an address to a multiple of align
func align32(addr, align uint32) uint32 {
	n := addr % align
	if n != 0 {
		addr += align - n
	}
	return addr
}
