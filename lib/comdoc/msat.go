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

// Allocate sectors for the SAT and MSAT
func (r *ComDoc) allocSectorTables() (satList, msatList []SecID) {
	// free existing sectors
	for i, j := range r.SAT {
		if j == SecIDSAT || j == SecIDMSAT {
			r.SAT[i] = SecIDFree
		}
	}
	// work out how many sectors are needed for both
	satPerSector := r.SectorSize / 4
	msatPerSector := satPerSector - 1
	for {
		if len(r.SAT)%satPerSector != 0 {
			panic("irregularly sized sector table")
		}
		satSectors := len(r.SAT) / satPerSector
		// 109 MSAT entries fit into the file header, the rest need more sectors
		msatSectors := (satSectors - msatInHeader + msatPerSector - 1) / msatPerSector
		// Check if there's room
		oldSize := len(r.SAT)
		freeList := r.makeFreeSectors(satSectors+msatSectors, false)
		if oldSize == len(r.SAT) {
			msatList = freeList[:msatSectors]
			satList = freeList[msatSectors:]
			break
		}
		// The SAT was extended so go around again to make sure that didn't
		// increase the requirements further
	}
	// Mark used sectors
	for _, i := range msatList {
		r.SAT[i] = SecIDMSAT
	}
	for _, i := range satList {
		r.SAT[i] = SecIDSAT
	}
	return satList, msatList
}

// Write an updated MSAT out to the header and msatSectors, with satSectors
// being the contents of the MSAT
func (r *ComDoc) writeMSAT(satSectors, msatSectors []SecID) error {
	satPerSector := r.SectorSize / 4
	msatPerSector := satPerSector - 1
	msatCount := msatInHeader + len(msatSectors)*msatPerSector
	msat := make([]SecID, msatCount)
	copy(msat, satSectors)
	for i := len(satSectors); i < msatCount; i++ {
		msat[i] = SecIDFree
	}
	copy(r.Header.MSAT[:], msat)
	msat = msat[msatInHeader:] // done with the first 109
	buf := bytes.NewBuffer(r.sectorBuf)
	nextSector := SecIDEndOfChain
	chunk := make([]SecID, r.SectorSize/4)
	for i := len(msatSectors) - 1; i >= 0; i-- { // each needs to link to the next, so walk backwards
		sector := msatSectors[i]
		j := i * msatPerSector
		copy(chunk, msat[j:])
		msat = msat[:j]
		chunk[msatPerSector] = nextSector
		nextSector = sector

		buf.Reset()
		binary.Write(buf, binary.LittleEndian, chunk)
		if err := r.writeSector(sector, buf.Bytes()); err != nil {
			return err
		}
	}
	r.Header.MSATNextSector = nextSector
	r.MSAT = msat
	return nil
}
