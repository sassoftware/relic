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

package comdoc

import (
	"bytes"
	"encoding/binary"
	"errors"
)

// Read the short sector allocation table
//
// The SSAT works the same way as the SAT, except that the indices correspond
// to positions within the short sector stream instead of the file at large,
// and those sectors are ShortSectorSize in length instead of SectorSize. It's
// also stored differently, using the SAT to chain to each subsequent block
// instead of using the MSAT array, in the same way that any other stream works.
func (r *ComDoc) readShortSAT() error {
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

// Free the old short-sector allocation table and write a new one
func (r *ComDoc) writeShortSAT() error {
	freeSectors(r.SAT, r.Header.SSATNextSector)
	perSector := r.SectorSize / 4
	freeList := r.makeFreeSectors(len(r.SSAT)/perSector, false)
	buf := bytes.NewBuffer(r.sectorBuf)
	first := SecIDEndOfChain
	previous := first
	for i, sector := range freeList {
		j := i * perSector
		chunk := r.SSAT[j : j+perSector]
		buf.Reset()
		_ = binary.Write(buf, binary.LittleEndian, chunk)
		if err := r.writeSector(sector, buf.Bytes()); err != nil {
			return err
		}
		if previous == SecIDEndOfChain {
			first = sector
		} else {
			r.SAT[previous] = sector
		}
		previous = sector
	}
	r.SAT[previous] = SecIDEndOfChain
	r.Header.SSATNextSector = first
	r.Header.SSATSectorCount = uint32(len(freeList))
	return nil
}

// Read a short sector at the given position.
//
// Short sectors work similarly to big sectors except they are smaller, have
// their own allocation table, and they point to a position within the "short
// sector stream" instead of within the file at large. The short sector stream
// is a regular stream whose first block is pointed to by the root storage
// dirent.
func (r *ComDoc) readShortSector(shortSector SecID, buf []byte) (int, error) {
	// figure out which big sector holds the short sector
	bigSectorIndex := int(shortSector) * r.ShortSectorSize / r.SectorSize
	bigSectorID := r.Files[r.rootStorage].NextSector
	for i := 0; i < bigSectorIndex; i++ {
		bigSectorID = r.SAT[bigSectorID]
	}
	// translate to a file position
	n := r.sectorToOffset(bigSectorID)
	n += int64(int(shortSector)*r.ShortSectorSize - bigSectorIndex*r.SectorSize)
	return r.File.ReadAt(buf, n)
}

// Write a short sector at the given position. This will allocate new space in
// the short-sector stream if needed.
func (r *ComDoc) writeShortSector(shortSector SecID, content []byte) error {
	if len(content) > r.ShortSectorSize {
		panic("excessive write")
	} else if len(content) < r.ShortSectorSize {
		buf := r.sectorBuf
		copy(buf, content)
		for i := len(content); i < r.ShortSectorSize; i++ {
			buf[i] = 0
		}
		content = buf[:r.ShortSectorSize]
	}
	// walk the short stream to find the big sector that holds the target small sector
	bigSectorIndex := int(shortSector) * r.ShortSectorSize / r.SectorSize
	offset := int(shortSector)*r.ShortSectorSize - bigSectorIndex*r.SectorSize
	root := &r.Files[r.rootStorage]
	bigSectorID := root.NextSector
	for ; bigSectorIndex > 0; bigSectorIndex-- {
		next := r.SAT[bigSectorID]
		if next < 0 {
			break
		}
		bigSectorID = next
	}
	if bigSectorIndex > 0 {
		// extend short sector stream
		freeList := r.makeFreeSectors(bigSectorIndex, false)
		for _, sector := range freeList {
			r.SAT[bigSectorID] = sector
			bigSectorID = sector
		}
		r.SAT[bigSectorID] = SecIDEndOfChain
	}
	n := r.sectorToOffset(bigSectorID) + int64(offset)
	if _, err := r.writer.WriteAt(content, n); err != nil {
		return err
	}
	streamLength := uint32(int(shortSector+1) * r.ShortSectorSize)
	if streamLength > root.StreamSize {
		root.StreamSize = streamLength
	}
	return nil
}
