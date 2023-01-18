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
	"io"
)

// Convert a sector ID to an absolute file position
func (r *ComDoc) sectorToOffset(sector SecID) int64 {
	if sector < 0 {
		return -1
	}
	return r.FirstSector + int64(sector)*int64(r.SectorSize)
}

// Read the specified sector
func (r *ComDoc) readSector(sector SecID, buf []byte) (int, error) {
	return r.File.ReadAt(buf, r.sectorToOffset(sector))
}

// Read the specified sector into a binary structure. It must be exactly 1
// sector in size already.
func (r *ComDoc) readSectorStruct(sector SecID, v interface{}) error {
	n, err := r.readSector(sector, r.sectorBuf)
	if err != nil && err != io.EOF {
		return err
	} else if n < r.SectorSize {
		return io.ErrUnexpectedEOF
	}
	return binary.Read(bytes.NewReader(r.sectorBuf), binary.LittleEndian, v)
}

// Write to a specified sector. Content will be padded with zeroes if it is
// less than a full sector in length.
func (r *ComDoc) writeSector(sector SecID, content []byte) error {
	if len(content) > r.SectorSize {
		panic("excessive write")
	} else if len(content) < r.SectorSize {
		buf := r.sectorBuf
		copy(buf, content)
		for i := len(content); i < r.SectorSize; i++ {
			buf[i] = 0
		}
		content = buf[:r.SectorSize]
	}
	_, err := r.writer.WriteAt(content, r.sectorToOffset(sector))
	return err
}

// Mark a chain of sectors as free
func freeSectors(sat []SecID, sector SecID) {
	for {
		nextSector := sat[sector]
		sat[sector] = SecIDFree
		if nextSector < 0 {
			break
		}
		sector = nextSector
	}
}

// Return a list of "count" free sectors or short sectors, extending the table if needed
func (r *ComDoc) makeFreeSectors(count int, short bool) []SecID {
	if count <= 0 {
		return nil
	}
	freeList := make([]SecID, 0, count)
	var sat []SecID
	if short {
		sat = r.SSAT
	} else {
		sat = r.SAT
	}
	// scan for existing free sectors
	for i, j := range sat {
		if j != SecIDFree {
			continue
		}
		freeList = append(freeList, SecID(i))
		count--
		if count == 0 {
			return freeList
		}
	}
	// extend the sector table
	sectorsPerBlock := r.SectorSize / 4
	needBlocks := (count + sectorsPerBlock - 1) / sectorsPerBlock
	oldCount := len(sat)
	newSAT := append(sat, make([]SecID, needBlocks*sectorsPerBlock)...)
	for i := oldCount; i < len(newSAT); i++ {
		newSAT[i] = SecIDFree
		if count > 0 {
			freeList = append(freeList, SecID(i))
			count--
		}
	}
	if short {
		r.SSAT = newSAT
	} else {
		r.SAT = newSAT
	}
	return freeList
}

// Read the sector allocation table.
//
// Each index within the table corresponds to a sector within the file itself.
// The value held at that index in the SAT either points to the ID of the
// sector holding the next chunk of data for that stream, or -2 to indicate
// there are no more sectors.
func (r *ComDoc) readSAT() error {
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

// Write the new sector allocation table to the listed sector IDs
func (r *ComDoc) writeSAT() error {
	satPerSector := r.SectorSize / 4
	buf := bytes.NewBuffer(r.sectorBuf)
	for i, sector := range r.MSAT {
		j := i * satPerSector
		buf.Reset()
		_ = binary.Write(buf, binary.LittleEndian, r.SAT[j:j+satPerSector])
		if err := r.writeSector(sector, buf.Bytes()); err != nil {
			return err
		}
	}
	return nil
}
