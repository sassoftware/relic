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
	"errors"
	"fmt"
	"io"
)

type streamReader struct {
	remaining  uint32
	nextSector SecID
	sat        []SecID
	sectorSize int
	readSector func(SecID, []byte) (int, error)
	buf, saved []byte
}

// Open a stream for reading
func (r *ComDoc) ReadStream(e *DirEnt) (io.Reader, error) {
	if e.Type != DirStream {
		return nil, errors.New("not a stream")
	}
	sr := &streamReader{
		remaining:  e.StreamSize,
		nextSector: e.NextSector,
	}
	if e.StreamSize < r.Header.MinStdStreamSize {
		sr.sectorSize = r.ShortSectorSize
		sr.sat = r.SSAT
		sr.readSector = r.readShortSector
	} else {
		sr.sectorSize = r.SectorSize
		sr.sat = r.SAT
		sr.readSector = r.readSector
	}
	sr.buf = make([]byte, sr.sectorSize)
	return sr, nil
}

func (sr *streamReader) Read(d []byte) (copied int, err error) {
	if sr.remaining == 0 {
		return 0, io.EOF
	} else if len(d) == 0 {
		return 0, nil
	}
	if int64(len(d)) > int64(sr.remaining) {
		d = d[:int(sr.remaining)]
	}
	// read from previously buffered sector
	if len(sr.saved) > 0 {
		n := copy(d, sr.saved)
		d = d[n:]
		sr.saved = sr.saved[n:]
		copied += n
		sr.remaining -= uint32(n)
	}
	// read whole sectors
	for len(d) >= sr.sectorSize {
		if sr.nextSector < 0 {
			return copied, errors.New("unexpected end to stream")
		}
		n, err := sr.readSector(sr.nextSector, d[:sr.sectorSize])
		if n > 0 {
			d = d[n:]
			copied += n
			sr.remaining -= uint32(n)
		}
		if err != io.EOF && err != nil {
			return copied, err
		} else if n < sr.sectorSize && sr.remaining > 0 {
			return copied, fmt.Errorf("short read of sector %d: expected %d bytes but got %d", sr.nextSector, sr.sectorSize, n)
		}
		sr.nextSector = sr.sat[sr.nextSector]
	}
	// read partial sector and buffer the rest
	if len(d) > 0 {
		if sr.nextSector < 0 {
			return copied, errors.New("unexpected end to stream")
		}
		// read the full sector
		sectorN, err := sr.readSector(sr.nextSector, sr.buf)
		if sectorN > 0 {
			// fill the rest of the result
			copyN := copy(d, sr.buf)
			copied += copyN
			sr.remaining -= uint32(copyN)
		}
		if err != io.EOF && err != nil {
			return copied, err
		} else if sectorN < sr.sectorSize && sr.remaining > 0 {
			// it's ok if the final sector is truncated if there are no more bytes in the stream
			return copied, fmt.Errorf("short read of sector %d: expected %d bytes but got %d", sr.nextSector, sr.remaining, sectorN)
		}
		// save the remainder, if anything
		sr.saved = sr.buf[len(d):]
		sr.nextSector = sr.sat[sr.nextSector]
	}
	return copied, nil
}

// Store a blob as a chain of sectors, updating the sector table (or
// short-sector table if "short" is set)  and return the first sector ID
func (r *ComDoc) addStream(contents []byte, short bool) (SecID, error) {
	var sectorSize int
	var sat, freeList []SecID
	if short {
		sectorSize = int(r.ShortSectorSize)
		needSectors := (len(contents) + sectorSize - 1) / sectorSize
		freeList = r.makeFreeSectors(needSectors, true)
		sat = r.SSAT
	} else {
		sectorSize = int(r.SectorSize)
		needSectors := (len(contents) + sectorSize - 1) / sectorSize
		freeList = r.makeFreeSectors(needSectors, false)
		sat = r.SAT
	}
	first := SecIDEndOfChain
	previous := first
	for _, i := range freeList {
		if previous == SecIDEndOfChain {
			first = i
		} else {
			sat[previous] = i
		}
		previous = i
		// write to file
		n := sectorSize
		if n > len(contents) {
			n = len(contents)
		}
		var err error
		if short {
			err = r.writeShortSector(i, contents[:n])
		} else {
			err = r.writeSector(i, contents[:n])
		}
		if err != nil {
			return 0, err
		}
		contents = contents[n:]
	}
	sat[previous] = SecIDEndOfChain
	if len(contents) > 0 {
		panic("didn't allocate enough sectors")
	}
	return first, nil
}
