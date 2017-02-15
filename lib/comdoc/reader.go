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

package comdoc

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os"
)

// Microsoft Compound Document File
// Reference: https://www.openoffice.org/sc/compdocfileformat.pdf
// ERRATA: The above document says the 0th sector is always 512 bytes into the
// file. This is not correct. If SectorSize > 512 bytes then the 0th sector is
// SectorSize bytes into the file.

type Reader struct {
	File            io.ReaderAt
	Header          *Header
	SectorSize      int
	ShortSectorSize int
	FirstSector     int64
	MSAT, SAT, SSAT []SecID
	Files           []*DirEnt
	RootStorage     *DirEnt

	sectorBuf []byte
}

func Open(path string) (*Reader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	return NewReader(f)
}

func NewReader(f io.ReaderAt) (*Reader, error) {
	header := new(Header)
	r := &Reader{
		File:   f,
		Header: header,
	}
	hf := io.NewSectionReader(f, 0, 512)
	if err := binary.Read(hf, binary.LittleEndian, header); err != nil {
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

// Convert a sector ID to an absolute file position
func (r *Reader) sectorToOffset(sector SecID) int64 {
	if sector < 0 {
		return -1
	}
	return r.FirstSector + int64(sector)*int64(r.SectorSize)
}

// Read the specified sector
func (r *Reader) readSector(sector SecID, buf []byte) error {
	_, err := r.File.ReadAt(buf, r.sectorToOffset(sector))
	return err
}

// Read the specified sector into a binary structure. It must be exactly 1
// sector in size already.
func (r *Reader) readSectorStruct(sector SecID, v interface{}) error {
	if err := r.readSector(sector, r.sectorBuf); err != nil {
		return err
	}
	return binary.Read(bytes.NewReader(r.sectorBuf), binary.LittleEndian, v)
}

// Read a short sector at the given position.
//
// Short sectors work similarly to big sectors except they are smaller, have
// their own allocation table, and they point to a position within the "short
// sector stream" instead of within the file at large. The short sector stream
// is a regular stream whose first block is pointed to by the root storage
// dirent.
func (r *Reader) readShortSector(shortSector SecID, buf []byte) error {
	// figure out which big sector holds the short sector
	bigSectorIndex := int(shortSector) * r.ShortSectorSize / r.SectorSize
	bigSectorId := r.RootStorage.NextSector
	for i := 0; i < bigSectorIndex; i++ {
		bigSectorId = r.SAT[bigSectorId]
	}
	// translate to a file position
	n := r.sectorToOffset(bigSectorId)
	n += int64(int(shortSector)*r.ShortSectorSize - bigSectorIndex*r.SectorSize)
	_, err := r.File.ReadAt(buf, n)
	return err
}

// Read the master/meta sector allocation table. It is an array of all the
// sectors holding pieces of the sector allocation table (SAT). The main file
// header holds 109 MSAT entries and MSATNextSector may point to a sector
// holding yet more. The last entry in each additional sector points to another
// sector holding more MSAT entries, or -2 if none.
func (r *Reader) readMSAT() error {
	msat := r.Header.MSAT[:]
	nextSector := r.Header.MSATNextSector
	count := r.SectorSize / 4
	values := make([]SecID, count)
	for nextSector >= 0 {
		if err := r.readSectorStruct(nextSector, values); err != nil {
			return err
		}
		msat = append(msat, values[:count-1]...)
		nextSector = values[count-1]
	}
	r.MSAT = msat
	return nil
}

// Read the sector allocation table.
//
// Each index within the table corresponds to a sector within the file itself.
// The value held at that index in the SAT either points to the ID of the
// sector holding the next chunk of data for that stream, or -2 to indicate
// there are no more sectors.
func (r *Reader) readSAT() error {
	count := r.SectorSize / 4
	sat := make([]SecID, count*int(r.Header.SATSectors))
	position := 0
	for _, sector := range r.MSAT {
		if sector < 0 {
			continue
		}
		if position >= len(sat) {
			return errors.New("msat has more sectors than indicated")
		}
		if err := r.readSectorStruct(sector, sat[position:position+count]); err != nil {
			return err
		}
		position += count
	}
	r.SAT = sat
	return nil
}

// Read the short sector allocation table
//
// The SSAT works the same way as the SAT, except that the indices correspond
// to positions within the short sector stream instead of the file at large,
// and those sectors are ShortSectorSize in length instead of SectorSize. It's
// also stored differently, using the SAT to chain to each subsequent block
// instead of using the MSAT array, in the same way that any other stream works.
func (r *Reader) readShortSAT() error {
	count := r.SectorSize / 4
	sat := make([]SecID, count*int(r.Header.SSATSectorCount))
	position := 0
	for sector := r.Header.SSATNextSector; sector >= 0; sector = r.SAT[sector] {
		if position >= len(sat) {
			return errors.New("ssat has more sectors than indicated")
		}
		if err := r.readSectorStruct(sector, sat[position:position+count]); err != nil {
			return err
		}
		position += count
	}
	r.SSAT = sat
	return nil
}

// Read all directory entries and identify the root storage
func (r *Reader) readDir() error {
	var files []*DirEnt
	values := make([]DirEnt, r.SectorSize/128)
	valid := make([]*DirEnt, r.SectorSize/128)
	for sector := r.Header.DirNextSector; sector >= 0; sector = r.SAT[sector] {
		if err := r.readSectorStruct(sector, values); err != nil {
			return err
		}
		valid = valid[:0]
		for _, dirent := range values {
			if dirent.Type == DirEmpty {
				continue
			}
			dptr := new(DirEnt)
			*dptr = dirent
			valid = append(valid, dptr)
		}
		files = append(files, valid...)
	}
	for _, dptr := range files {
		if dptr.Type == DirRoot {
			r.RootStorage = dptr
		}
	}
	r.Files = files
	return nil
}
