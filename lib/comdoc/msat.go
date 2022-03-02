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
)

// Read the master/meta sector allocation table. It is an array of all the
// sectors holding pieces of the sector allocation table (SAT). The main file
// header holds 109 MSAT entries and MSATNextSector may point to a sector
// holding yet more. The last entry in each additional sector points to another
// sector holding more MSAT entries, or -2 if none.
func (r *ComDoc) readMSAT() error {
	r.MSAT = r.Header.MSAT[:]
	r.msatList = nil
	nextSector := r.Header.MSATNextSector
	count := r.SectorSize / 4
	values := make([]SecID, count)
	for nextSector >= 0 {
		if err := r.readSectorStruct(nextSector, values); err != nil {
			return err
		}
		r.MSAT = append(r.MSAT, values[:count-1]...)
		r.msatList = append(r.msatList, nextSector)
		nextSector = values[count-1]
	}
	// trim free slots
	for i := len(r.MSAT) - 1; i >= 0; i-- {
		if r.MSAT[i] >= 0 {
			r.MSAT = r.MSAT[:i+1]
			break
		}
	}
	return nil
}

// Allocate sectors for the SAT and MSAT
func (r *ComDoc) allocSectorTables() {
	// work out how many sectors are needed for both
	satPerSector := r.SectorSize / 4
	msatPerSector := satPerSector - 1
	for {
		if len(r.SAT)%satPerSector != 0 {
			panic("irregularly sized sector table")
		}
		satSectors := len(r.SAT) / satPerSector
		if satSectors > len(r.MSAT) {
			// allocate a new SAT sector
			sector := r.makeFreeSectors(1, false)[0]
			r.MSAT = append(r.MSAT, sector)
			r.SAT[sector] = SecIDSAT
			// a new SAT might be needed so check again
			continue
		}
		// 109 MSAT entries fit into the file header, the rest need more sectors
		msatSectors := (len(r.MSAT) - msatInHeader + msatPerSector - 1) / msatPerSector
		if msatSectors > len(r.msatList) {
			// allocate a new MSAT sector
			sector := r.makeFreeSectors(1, false)[0]
			r.msatList = append(r.msatList, sector)
			r.SAT[sector] = SecIDMSAT
			// a new SAT might be needed so check again
			continue
		}
		break
	}
}

// Write an updated MSAT out to the header and msatSectors, with satSectors
// being the contents of the MSAT
func (r *ComDoc) writeMSAT() error {
	satPerSector := r.SectorSize / 4
	msatPerSector := satPerSector - 1
	// round MSAT up to the next full sector and mark all unused spaces as free
	msatCount := msatInHeader + len(r.msatList)*msatPerSector
	msat := make([]SecID, msatCount)
	copy(msat, r.MSAT)
	for i := len(r.MSAT); i < msatCount; i++ {
		msat[i] = SecIDFree
	}
	// copy the first 109 into the file header
	copy(r.Header.MSAT[:], msat)
	msat = msat[msatInHeader:]
	// write remaining sectors
	buf := bytes.NewBuffer(r.sectorBuf)
	chunk := make([]SecID, r.SectorSize/4)
	for i, sector := range r.msatList {
		j := i * msatPerSector
		copy(chunk, msat[j:j+msatPerSector])
		// set pointer to next MSAT sector
		if i < len(r.msatList)-1 {
			chunk[msatPerSector] = r.msatList[i+1]
		} else {
			chunk[msatPerSector] = SecIDEndOfChain
		}
		// write
		buf.Reset()
		_ = binary.Write(buf, binary.LittleEndian, chunk)
		if err := r.writeSector(sector, buf.Bytes()); err != nil {
			return err
		}
	}
	if len(r.msatList) > 0 {
		r.Header.MSATNextSector = r.msatList[0]
	} else {
		r.Header.MSATNextSector = SecIDEndOfChain
	}
	return nil
}
