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

func readNAt(r io.ReaderAt, offset int64, len int) ([]byte, error) {
	buf := make([]byte, len)
	_, err := r.ReadAt(buf, offset)
	return buf, err
}

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
