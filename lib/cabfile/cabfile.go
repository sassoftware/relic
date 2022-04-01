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

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"errors"
	"hash"
	"io"
	"io/ioutil"

	"github.com/sassoftware/relic/v7/lib/binpatch"
)

// Calculate the digest (imprint) of a CAB file for signing purposes
func Digest(r io.Reader, hashFunc crypto.Hash) (*CabinetDigest, error) {
	var d hash.Hash
	var dw io.Writer
	if hashFunc == 0 {
		dw = ioutil.Discard
	} else {
		d = hashFunc.New()
		dw = d
	}
	cab := new(Cabinet)
	if err := binary.Read(r, binary.LittleEndian, &cab.Header); err != nil {
		return nil, err
	}
	if cab.Header.Magic != Magic {
		return nil, errors.New("not a cab file")
	}

	outHeader := cab.Header
	if cab.Header.Flags&FlagReservePresent != 0 {
		if err := binary.Read(r, binary.LittleEndian, &cab.ReserveHeader); err != nil {
			return nil, err
		}
		if cab.ReserveHeader.HeaderSize > 0 {
			if cab.ReserveHeader.HeaderSize != 20 {
				return nil, errors.New("unknown reserved data")
			}
			cab.SignatureHeader = new(SignatureHeader)
			if err := binary.Read(r, binary.LittleEndian, cab.SignatureHeader); err != nil {
				return nil, err
			}
			if cab.Header.TotalSize != cab.SignatureHeader.CabinetSize {
				return nil, errors.New("mismatch between cabinet size and signature header size")
			}
		} else {
			return nil, errors.New("unknown reserved data")
		}
		if cab.ReserveHeader.FolderSize != 0 || cab.ReserveHeader.DataSize != 0 {
			return nil, errors.New("unknown reserved data")
		}
	}
	if cab.Header.Flags&(FlagPrevCabinet|FlagNextCabinet) != 0 {
		return nil, errors.New("multipart cab files are not supported")
	} else if cab.Header.Flags&^FlagReservePresent != 0 {
		return nil, errors.New("unsupported flags in cabinet file")
	}
	var addOffset uint32
	var outSigHeader SignatureHeader
	if cab.SignatureHeader == nil {
		// make a new header and increment all the file offsets to make room for it
		addOffset = 24
		outHeader.TotalSize += addOffset
		outHeader.Flags |= FlagReservePresent
		outHeader.OffsetFiles += addOffset
		outSigHeader.Unknown1 = 0x100000
		outSigHeader.CabinetSize = outHeader.TotalSize
	} else {
		outSigHeader = *cab.SignatureHeader
	}
	// digest the header
	sb := sigBlob{
		Magic:       outHeader.Magic,
		TotalSize:   outHeader.TotalSize,
		Reserved2:   outHeader.Reserved2,
		OffsetFiles: outHeader.OffsetFiles,
		Reserved3:   outHeader.Reserved3,
		Version:     outHeader.Version,
		NumFolders:  outHeader.NumFolders,
		NumFiles:    outHeader.NumFiles,
		Flags:       outHeader.Flags,
		SetID:       outHeader.SetID,
		SigUnknown3: outSigHeader.Unknown3,
	}
	_ = binary.Write(dw, binary.LittleEndian, sb)
	// save the updated header for writing out later
	patched := bytes.NewBuffer(make([]byte, 0, outHeader.OffsetFiles))
	_ = binary.Write(patched, binary.LittleEndian, outHeader)
	_ = binary.Write(patched, binary.LittleEndian, ReserveHeader{20, 0, 0})
	_ = binary.Write(patched, binary.LittleEndian, outSigHeader)
	w := io.MultiWriter(dw, patched)
	var fh FolderHeader
	for i := 0; i < int(cab.Header.NumFolders); i++ {
		if err := binary.Read(r, binary.LittleEndian, &fh); err != nil {
			return nil, err
		}
		fh.Offset += addOffset
		_ = binary.Write(w, binary.LittleEndian, fh)
	}
	if _, err := io.CopyN(dw, r, int64(cab.Header.TotalSize-cab.Header.OffsetFiles)); err != nil {
		return nil, err
	}
	if cab.SignatureHeader != nil {
		cab.Signature = make([]byte, cab.SignatureHeader.SignatureSize)
		if _, err := io.ReadFull(r, cab.Signature); err != nil {
			return nil, err
		}
	}
	if _, err := r.Read(make([]byte, 1)); err == nil {
		return nil, errors.New("trailing garbage after cabinet")
	} else if err != io.EOF {
		return nil, err
	}
	var imprint []byte
	if d != nil {
		imprint = d.Sum(nil)
	}
	return &CabinetDigest{cab, imprint, hashFunc, patched.Bytes()}, nil
}

// Parse the cabinet file header and return it
func Parse(r io.Reader) (*Cabinet, error) {
	digest, err := Digest(r, 0)
	if err != nil {
		return nil, err
	}
	return digest.Cabinet, nil
}

// Create a patchset that will apply the given signature blob to a previously
// digested cabinet file, replacing any existing signature
func (d *CabinetDigest) MakePatch(pkcs []byte) *binpatch.PatchSet {
	// pad signature to 8 byte boundary
	padded := make([]byte, (len(pkcs)+7)/8*8)
	copy(padded, pkcs)
	// update the signature header with the final size
	hdr := d.Patched
	binary.LittleEndian.PutUint32(hdr[48:], uint32(len(padded)))
	p := binpatch.New()
	p.Add(0, int64(d.Cabinet.Header.OffsetFiles), hdr)
	p.Add(int64(d.Cabinet.Header.TotalSize), int64(d.Cabinet.SignatureHeader.Size()), padded)
	return p
}
