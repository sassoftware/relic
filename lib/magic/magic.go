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

package magic

import (
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path"
	"strings"

	"github.com/xi2/xz"
)

type FileType int
type CompressionType int

const (
	FileTypeUnknown FileType = iota
	FileTypeRPM
	FileTypeDEB
	FileTypePGP
	FileTypeJAR
	FileTypePKCS7
	FileTypePECOFF
	FileTypeMSI
	FileTypeCAB
	FileTypeAppManifest
	FileTypeCAT
	FileTypeAPPX
	FileTypeVSIX
	FileTypeXAP
	FileTypeAPK
	FileTypeMachO
	FileTypeMachOFat
	FileTypeIPA
	FileTypeXAR
)

const (
	CompressedNone CompressionType = iota
	CompressedGzip
	CompressedXz
)

func hasPrefix(br *bufio.Reader, blob []byte) bool {
	return atPosition(br, blob, 0)
}

func contains(br *bufio.Reader, blob []byte, n int) bool {
	d, _ := br.Peek(n)
	if len(d) < len(blob) {
		return false
	}
	return bytes.Contains(d, blob)
}

func atPosition(br *bufio.Reader, blob []byte, n int) bool {
	l := n + len(blob)
	d, _ := br.Peek(l)
	if len(d) < l {
		return false
	}
	return bytes.Equal(d[n:], blob)
}

// Detect a handful of package and signature file types based on the first few
// bytes of the file contents.
func Detect(r io.Reader) FileType {
	br := bufio.NewReader(r)
	switch {
	case hasPrefix(br, []byte{0xed, 0xab, 0xee, 0xdb}):
		return FileTypeRPM
	case hasPrefix(br, []byte("!<arch>\ndebian")):
		return FileTypeDEB
	case hasPrefix(br, []byte("-----BEGIN PGP")):
		return FileTypePGP
	case contains(br, []byte{0x06, 0x09, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x0A, 0x01}, 256):
		// OID certTrustList
		return FileTypeCAT
	case contains(br, []byte{0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02}, 256):
		// OID signedData
		return FileTypePKCS7
	case isTar(br):
		return detectTar(br)
	case hasPrefix(br, []byte("MZ")):
		if blob, _ := br.Peek(0x3e); len(blob) == 0x3e {
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
	case contains(br, []byte("<assembly"), 256),
		contains(br, []byte(":assembly"), 256):
		return FileTypeAppManifest
	case hasPrefix(br, []byte{0xcf, 0xfa, 0xed, 0xfe}), hasPrefix(br, []byte{0xce, 0xfa, 0xed, 0xfe}):
		return FileTypeMachO
	case hasPrefix(br, []byte{0xca, 0xfe, 0xba, 0xbe}):
		return FileTypeMachOFat
	case hasPrefix(br, []byte{0x78, 0x61, 0x72, 0x21}):
		return FileTypeXAR
	case hasPrefix(br, []byte{0x89}), hasPrefix(br, []byte{0xc2}), hasPrefix(br, []byte{0xc4}):
		return FileTypePGP
	}
	return FileTypeUnknown
}

func DetectCompressed(f *os.File) (FileType, CompressionType) {
	br := bufio.NewReader(f)
	ftype := FileTypeUnknown
	switch {
	case hasPrefix(br, []byte{0x1f, 0x8b}):
		zr, err := gzip.NewReader(br)
		if err == nil {
			zbr := bufio.NewReader(zr)
			if isTar(zbr) {
				ftype = detectTar(zbr)
			}
		}
		return ftype, CompressedGzip
	case hasPrefix(br, []byte("\xfd7zXZ\x00")):
		zr, err := xz.NewReader(br, 0)
		if err == nil {
			zbr := bufio.NewReader(zr)
			if isTar(zbr) {
				ftype = detectTar(zbr)
			}
		}
		return ftype, CompressedXz
	case hasPrefix(br, []byte{0x50, 0x4b, 0x03, 0x04}):
		return detectZip(f), CompressedNone
	}
	return Detect(br), CompressedNone
}

func Decompress(r io.Reader, ctype CompressionType) (io.Reader, error) {
	switch ctype {
	case CompressedNone:
		return r, nil
	case CompressedGzip:
		return gzip.NewReader(r)
	case CompressedXz:
		return xz.NewReader(r, 0)
	default:
		return nil, errors.New("invalid compression type")
	}
}

func isTar(br *bufio.Reader) bool {
	return atPosition(br, []byte("ustar"), 257)
}

func detectTar(r io.Reader) FileType {
	return FileTypeUnknown
}

func detectZip(f *os.File) FileType {
	size, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		return FileTypeUnknown
	}
	inz, err := zip.NewReader(f, size)
	if err != nil {
		return FileTypeUnknown
	}
	var isJar bool
	for _, zf := range inz.File {
		name := zf.Name
		if strings.HasPrefix(name, "/") {
			name = "." + name
		}
		name = path.Clean(name)
		switch name {
		case "AndroidManifest.xml":
			return FileTypeAPK
		case "AppManifest.xaml":
			return FileTypeXAP
		case "AppxManifest.xml", "AppxMetadata/AppxBundleManifest.xml":
			return FileTypeAPPX
		case "extension.vsixmanifest":
			return FileTypeVSIX
		case "META-INF/MANIFEST.MF":
			// APKs are also JARs so save this for last
			isJar = true
		}
		switch {
		case strings.HasSuffix(name, ".app/Info.plist"):
			return FileTypeIPA
		case strings.HasSuffix(name, ".app/Contents/Info.plist"):
			return FileTypeIPA
		}
	}
	if isJar {
		return FileTypeJAR
	}
	return FileTypeUnknown
}
