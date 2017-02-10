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

package authenticode

import (
	"bytes"
	"encoding/binary"
	"io"
)

// read bytes at an offset and return a byte slice
func readNAt(r io.ReaderAt, offset int64, len int) ([]byte, error) {
	buf := make([]byte, len)
	_, err := r.ReadAt(buf, offset)
	return buf, err
}

// read a binary structure at an offset
func readBinaryAt(r io.ReaderAt, offset int64, len int64, value interface{}) error {
	sr := io.NewSectionReader(r, offset, len)
	size := binary.Size(value)
	reader := io.Reader(sr)
	empty := int64(size) - len
	if empty > 0 {
		reader = io.MultiReader(reader, bytes.NewBuffer(make([]byte, int(empty))))
	}
	return binary.Read(sr, binary.LittleEndian, value)
}

// read bytes from a stream and return a byte slice, also feeding a hash
func readAndHash(r io.Reader, d io.Writer, n int) ([]byte, error) {
	if n == 0 {
		return nil, nil
	}
	buf := make([]byte, n)
	if _, err := r.Read(buf); err != nil {
		return nil, err
	}
	d.Write(buf)
	return buf, nil
}

// read from a byte slice into a structure
func binaryReadBytes(buf []byte, val interface{}) error {
	return binary.Read(bytes.NewReader(buf), binary.LittleEndian, val)
}
