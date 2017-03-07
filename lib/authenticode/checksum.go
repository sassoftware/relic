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

package authenticode

import (
	"encoding/binary"
	"errors"
	"hash"
	"io"
	"os"
)

// An undocumented, non-CRC checksum used in PE images
// https://www.codeproject.com/Articles/19326/An-Analysis-of-the-Windows-PE-Checksum-Algorithm

func FixPEChecksum(f *os.File) error {
	if _, err := f.Seek(0, 0); err != nil {
		return err
	}
	peStart, err := readDosHeader(f, nil)
	if err != nil {
		return err
	}
	ck := NewPEChecksum(int(peStart))
	if _, err := f.Seek(0, 0); err != nil {
		return err
	}
	if _, err := io.Copy(ck, f); err != nil {
		return err
	}
	if _, err := f.WriteAt(ck.Sum(nil), peStart+88); err != nil {
		return err
	}
	return nil
}

type peChecksum struct {
	cksumPos  int
	sum, size uint32
}

// Hasher that calculates the undocumented, non-CRC checksum used in PE images.
// peStart is the offset found at 0x3c in the DOS header.
func NewPEChecksum(peStart int) hash.Hash {
	var cksumPos int
	if peStart <= 0 {
		cksumPos = -1
	} else {
		cksumPos = peStart + 88
	}
	return &peChecksum{cksumPos, 0, 0}
}

func (peChecksum) Size() int {
	return 4
}

func (peChecksum) BlockSize() int {
	return 2
}

func (h *peChecksum) Reset() {
	h.cksumPos = -1
	h.sum = 0
	h.size = 0
}

func (h *peChecksum) Write(d []byte) (int, error) {
	if len(d)%2 != 0 {
		return 0, errors.New("odd write")
	}
	ckpos := -1
	if h.cksumPos > len(d) {
		h.cksumPos -= len(d)
	} else if h.cksumPos >= 0 {
		ckpos = h.cksumPos
		h.cksumPos = -1
	}
	sum := h.sum
	for i := 0; i < len(d); i += 2 {
		val := uint32(d[i+1])<<8 | uint32(d[i])
		if i == ckpos || i == ckpos+2 {
			val = 0
		}
		sum += val
		sum = 0xffff & (sum + (sum >> 16))
	}
	h.sum = sum
	h.size += uint32(len(d))
	return len(d), nil
}

func (h *peChecksum) Sum(buf []byte) []byte {
	sum := h.sum
	sum = 0xffff & (sum + (sum >> 16))
	sum += h.size
	d := make([]byte, 4)
	binary.LittleEndian.PutUint32(d, sum)
	return append(buf, d...)
}
