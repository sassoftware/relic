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

package cabfile

import "crypto"

const Magic = 0x4643534d // MSCF

type CabinetFlag uint16

const (
	FlagPrevCabinet CabinetFlag = 1 << iota
	FlagNextCabinet
	FlagReservePresent
)

type Header struct {
	Magic       uint32
	Reserved1   uint32
	TotalSize   uint32
	Reserved2   uint32
	OffsetFiles uint32
	Reserved3   uint32
	Version     uint16
	NumFolders  uint16
	NumFiles    uint16
	Flags       CabinetFlag
	SetID       uint16
	CabNumber   uint16
}

const reserveHeaderSize = 4

type ReserveHeader struct {
	HeaderSize uint16
	FolderSize uint8
	DataSize   uint8
}

const signatureHeaderSize = 20

type SignatureHeader struct {
	Unknown1           uint32
	CabinetSize        uint32
	SignatureSize      uint32
	Unknown2, Unknown3 uint32
}

func (sh *SignatureHeader) Size() uint32 {
	if sh == nil {
		return 0
	}
	return sh.SignatureSize
}

type FolderHeader struct {
	Offset      uint32
	NumData     uint16
	Compression uint16
}

// the pieces of Header that are part of the signature
type sigBlob struct {
	// skipped fields: Reserved1, CabNumber
	Magic       uint32
	TotalSize   uint32
	Reserved2   uint32
	OffsetFiles uint32
	Reserved3   uint32
	Version     uint16
	NumFolders  uint16
	NumFiles    uint16
	Flags       CabinetFlag
	SetID       uint16
	SigUnknown3 uint32
}

type Cabinet struct {
	Header          Header
	ReserveHeader   ReserveHeader
	ReserveData     []byte
	SignatureHeader *SignatureHeader
	Signature       []byte
}

type CabinetDigest struct {
	Cabinet  *Cabinet
	Imprint  []byte
	HashFunc crypto.Hash
	Patched  []byte
}
