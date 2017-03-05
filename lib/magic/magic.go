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
	"bufio"
	"bytes"
	"encoding/binary"
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
	FileTypeCAB
	FileTypeAppManifest
)

func hasPrefix(br *bufio.Reader, blob []byte) bool {
	d, _ := br.Peek(len(blob))
	if len(d) < len(blob) {
		return false
	}
	return bytes.Equal(d, blob)
}

func contains(br *bufio.Reader, blob []byte, n int) bool {
	d, _ := br.Peek(n)
	if len(d) < len(blob) {
		return false
	}
	return bytes.Contains(d, blob)
}

func Detect(r io.Reader) FileType {
	br := bufio.NewReader(r)
	switch {
	case hasPrefix(br, []byte{0xed, 0xab, 0xee, 0xdb}):
		return FileTypeRPM
	case hasPrefix(br, []byte("!<arch>\ndebian")):
		return FileTypeDEB
	case hasPrefix(br, []byte("-----BEGIN PGP")),
		hasPrefix(br, []byte{0x89, 0x01}),
		hasPrefix(br, []byte{0xc2, 0xc0}):
		return FileTypePGP
	case hasPrefix(br, []byte{0x50, 0x4b, 0x03, 0x04}):
		blob, _ := br.Peek(28)
		if len(blob) == 28 {
			fnLen := binary.LittleEndian.Uint16(blob[26:28])
			if blob, err := br.Peek(31 + int(fnLen)); err == nil {
				if blob[31+fnLen] == 0xca && blob[30+fnLen] == 0xfe {
					return FileTypeJAR
				}
				if bytes.Index(blob, []byte("META-INF/")) >= 0 {
					return FileTypeJAR
				}
			}
		}
	case contains(br, []byte{0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02}, 256):
		return FileTypePKCS7
	case hasPrefix(br, []byte("MZ")):
		blob, _ := br.Peek(0x3e)
		if len(blob) == 0x3e {
			reloc := binary.LittleEndian.Uint16(blob[0x3c:0x3e])
			if blob, err := br.Peek(int(reloc) + 4); err == nil {
				if bytes.Equal(blob[reloc:reloc+4], []byte("PE\x00\x00")) {
					return FileTypePECOFF
				}
			}
		}
	case hasPrefix(br, []byte{0xd0, 0xcf}):
		return FileTypeMSI
	case hasPrefix(br, []byte("MSCF")):
		return FileTypeCAB
	case contains(br, []byte("<assembly "), 256),
		contains(br, []byte(":assembly "), 256):
		return FileTypeAppManifest
	}
	return FileTypeUnknown
}
