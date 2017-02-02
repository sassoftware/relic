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

package magic

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

type FileType int

const (
	FileTypeUnknown = iota
	FileTypeRPM
	FileTypeDEB
	FileTypePGP
	FileTypeJAR
	FileTypePKCS7
	FileTypePECOFF
	FileTypeMSI
)

func Detect(r io.Reader) FileType {
	var buf [1024]byte
	blob := buf[:]
	if _, err := r.Read(blob); err != nil {
		return FileTypeUnknown
	}
	switch {
	case bytes.HasPrefix(blob, []byte{0xed, 0xab, 0xee, 0xdb}):
		return FileTypeRPM
	case bytes.HasPrefix(blob, []byte("=!<arch>\ndebian")):
		return FileTypeDEB
	case bytes.HasPrefix(blob, []byte("-----BEGIN PGP")),
		bytes.HasPrefix(blob, []byte{0x89, 0x01}),
		bytes.HasPrefix(blob, []byte{0xc2, 0xc0}):
		return FileTypePGP
	case bytes.HasPrefix(blob, []byte{0x50, 0x4b, 0x03, 0x04}):
		fnLen := binary.LittleEndian.Uint16(blob[26:28])
		if blob[31+fnLen] == 0xca && blob[30+fnLen] == 0xfe {
			return FileTypeJAR
		}
		if bytes.Index(blob, []byte("META-INF/")) >= 0 {
			return FileTypeJAR
		}
	case bytes.Index(blob, []byte{0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02}) >= 0:
		return FileTypePKCS7
	case bytes.HasPrefix(blob, []byte("MZ")):
		reloc := binary.LittleEndian.Uint16(blob[0x3c:0x3e])
		fmt.Printf("%d\n", reloc)
		if bytes.Equal(blob[reloc:reloc+4], []byte("PE\x00\x00")) {
			return FileTypePECOFF
		}
	case bytes.HasPrefix(blob, []byte{0xd0, 0xcf}):
		return FileTypeMSI
	}
	return FileTypeUnknown
}
