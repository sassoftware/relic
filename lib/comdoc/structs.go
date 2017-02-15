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
	"unicode/utf16"
)

type SecID int32
type DirType uint8

const (
	SecIDFree       SecID = -1
	SecIDEndOfChain SecID = -2
	SecIDSAT        SecID = -3
	SecIDMSAT       SecID = -4

	DirEmpty   DirType = 0
	DirStorage DirType = 1
	DirStream  DirType = 2
	DirRoot    DirType = 5

	byteOrderMarker uint16 = 0xfffe
)

var fileMagic = []byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1}

type Header struct {
	Magic            [8]byte
	Uid              [16]byte
	Revision         uint16
	Version          uint16
	ByteOrder        uint16
	SectorSize       uint16 // power of 2
	ShortSectorSize  uint16 // power of 2
	_                [10]byte
	SATSectors       uint32
	DirNextSector    SecID
	_                uint32
	MinStdStreamSize uint32
	SSATNextSector   SecID
	SSATSectorCount  uint32
	MSATNextSector   SecID
	MSATSectorCount  uint32
	MSAT             [109]SecID
}

type DirEnt struct {
	NameRunes   [32]uint16
	NameLength  uint16
	Type        DirType
	RedIsBlack  uint8
	LeftChild   uint32
	RightChild  uint32
	StorageRoot uint32
	Uid         [16]byte
	UserFlags   uint32
	CreateTime  uint64
	ModifyTime  uint64
	NextSector  SecID
	StreamSize  uint32
	_           uint32
}

func (e DirEnt) Name() string {
	used := e.NameLength/2 - 1
	if e.Type == DirEmpty || used > 32 {
		return ""
	}
	return string(utf16.Decode(e.NameRunes[:used]))
}
