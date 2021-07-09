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

// Microsoft Compound Document File
// Reference: https://www.openoffice.org/sc/compdocfileformat.pdf
// ERRATA: The above document says the 0th sector is always 512 bytes into the
// file. This is not correct. If SectorSize > 512 bytes then the 0th sector is
// SectorSize bytes into the file.
package comdoc

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os"
)

// CDF file open for reading or writing
type ComDoc struct {
	File            io.ReaderAt
	Header          *Header
	SectorSize      int
	ShortSectorSize int
	FirstSector     int64
	// MSAT is a list of sector IDs holding a SAT
	MSAT []SecID
	// SAT is a table where the index is the sector ID and the value is a pointer to the next sector ID in the same stream
	SAT   []SecID
	SSAT  []SecID
	Files []DirEnt

	sectorBuf   []byte
	changed     bool
	rootStorage int     // index into files
	rootFiles   []int   // index into Files
	msatList    []SecID // list of sector IDs holding a MSAT
	writer      *os.File
	closer      io.Closer
}

// Open a CDF file for reading
func ReadPath(path string) (*ComDoc, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	return openFile(f, nil, f)
}

// Open a CDF file for reading and writing
func WritePath(path string) (*ComDoc, error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	return openFile(f, f, f)
}

// Parse an already-open CDF file for reading
func ReadFile(reader io.ReaderAt) (*ComDoc, error) {
	return openFile(reader, nil, nil)
}

// Parse an already-open CDF file for reading and writing
func WriteFile(f *os.File) (*ComDoc, error) {
	return openFile(f, f, nil)
}

func openFile(reader io.ReaderAt, writer *os.File, closer io.Closer) (*ComDoc, error) {
	header := new(Header)
	r := &ComDoc{
		File:   reader,
		Header: header,
		writer: writer,
		closer: closer,
	}
	sr := io.NewSectionReader(reader, 0, 512)
	if err := binary.Read(sr, binary.LittleEndian, header); err != nil {
		return nil, err
	}
	if !bytes.Equal(header.Magic[:], fileMagic) {
		return nil, errors.New("not a compound document file")
	}
	if header.ByteOrder != byteOrderMarker {
		return nil, errors.New("incorrect byte order marker")
	}
	if header.SectorSize < 5 || header.SectorSize > 28 || header.ShortSectorSize >= header.SectorSize {
		return nil, errors.New("unreasonable header values")
	}
	r.SectorSize = 1 << header.SectorSize
	r.ShortSectorSize = 1 << header.ShortSectorSize
	if r.SectorSize < 512 {
		r.FirstSector = 512
	} else {
		r.FirstSector = int64(r.SectorSize)
	}
	r.sectorBuf = make([]byte, r.SectorSize)

	if err := r.readMSAT(); err != nil {
		return nil, err
	}
	if err := r.readSAT(); err != nil {
		return nil, err
	}
	if err := r.readShortSAT(); err != nil {
		return nil, err
	}
	if err := r.readDir(); err != nil {
		return nil, err
	}
	return r, nil
}
