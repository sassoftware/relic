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

package signappx

import (
	"archive/zip"
	"bufio"
	"crypto/hmac"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	fileHeaderSignature      = 0x04034b50
	directoryHeaderSignature = 0x02014b50
	directoryEndSignature    = 0x06054b50
	directory64LocSignature  = 0x07064b50
	directory64EndSignature  = 0x06064b50
	dataDescriptorSignature  = 0x08074b50
	fileHeaderLen            = 30
	directoryHeaderLen       = 46
	directoryEndLen          = 22
	directory64LocLen        = 20
	directory64EndLen        = 56
	dataDescriptorLen        = 16
	dataDescriptor64Len      = 24
)

type zipCentralDir struct {
	Signature        uint32
	CreatorVersion   uint16
	ReaderVersion    uint16
	Flags            uint16
	Method           uint16
	ModifiedTime     uint16
	ModifiedDate     uint16
	CRC32            uint32
	CompressedSize   uint32
	UncompressedSize uint32
	FilenameLen      uint16
	ExtraLen         uint16
	CommentLen       uint16
	StartDisk        uint16
	InternalAttrs    uint16
	ExternalAttrs    uint32
	Offset           uint32
}

type zip64End struct {
	Signature      uint32
	RecordSize     uint64
	CreatorVersion uint16
	ReaderVersion  uint16
	Disk           uint32
	FirstDisk      uint32
	DiskCDCount    uint64
	TotalCDCount   uint64
	CDSize         uint64
	CDOffset       uint64
}

type zipEndRecord struct {
	// zip64 locator
	Signature64 uint32
	Disk64      uint32
	Offset64    uint64
	DiskCount64 uint32
	// regular end record
	Signature     uint32
	DiskNumber    uint16
	DiskCD        uint16
	DiskCDCount   uint16
	TotalCDCount  uint16
	CDSize        uint32
	CDOffset      uint32
	CommentLength uint16
}

type zipLocalHeader struct {
	Signature        uint32
	ReaderVersion    uint16
	Flags            uint16
	Method           uint16
	ModifiedTime     uint16
	ModifiedDate     uint16
	CRC32            uint32
	CompressedSize   uint32
	UncompressedSize uint32
	FilenameLen      uint16
	ExtraLen         uint16
}

type zipDataDesc struct {
	Signature        uint32
	CRC32            uint32
	CompressedSize   uint32
	UncompressedSize uint32
}

type zipDataDesc64 struct {
	Signature        uint32
	CRC32            uint32
	CompressedSize   uint64
	UncompressedSize uint64
}

func verifyMeta(r io.ReaderAt, size int64, inz *zip.Reader, sig *AppxSignature, skipDigests bool) error {
	// AXPC is a hash of everything except the central directory and signature file
	axpc := sig.Hash.New()
	var nextRead, nextWrite int64
	for _, f := range inz.File {
		skipFile := f.Name == appxSignature
		endOfFile, written, err := digestFile(f, r, axpc, skipFile || skipDigests)
		if err != nil {
			return fmt.Errorf("verifying zip metadata: %s", err)
		}
		nextRead = endOfFile
		if !skipFile {
			nextWrite += written
			// nothing should come after a skipped file (i.e. the signature);
			// make sure no files have "moved" during the filtering process
			if nextWrite != nextRead {
				return fmt.Errorf("verifying zip metadata: %s", "gap in zip file")
			}
		}
	}
	if !skipDigests {
		calc := axpc.Sum(nil)
		if expected := sig.HashValues["AXPC"]; !hmac.Equal(calc, expected) {
			return fmt.Errorf("appx digest mismatch for zip contents: calculated %x != found %x", calc, expected)
		}
	}
	// AXCD is a hash of the zip central directory with the signature file removed
	axcd := sig.Hash.New()
	buf := bufio.NewReader(io.NewSectionReader(r, nextRead, size-nextRead))
	nrec := uint64(0)
	dirStart := nextWrite
	dirSize := int64(0)
	for _, f := range inz.File {
		written, err := digestFileHeader(f, buf, axcd)
		if err != nil {
			return fmt.Errorf("verifying zip metadata: %s", err)
		}
		if f.Name != appxSignature {
			dirSize += written
			nrec++
		}
	}
	if err := digestDirEnd(buf, axcd, dirStart, dirSize, nrec); err != nil {
		return fmt.Errorf("verifying zip metadata: %s", err)
	}
	calc := axcd.Sum(nil)
	if expected := sig.HashValues["AXCD"]; !hmac.Equal(calc, expected) {
		return fmt.Errorf("appx digest mismatch for zip directory: calculated %x != found %x", calc, expected)
	}
	return nil
}

func digestFile(f *zip.File, r io.ReaderAt, w io.Writer, skipDigests bool) (int64, int64, error) {
	dataOffset, err := f.DataOffset()
	if err != nil {
		return 0, 0, err
	}
	headerOffset := dataOffset - fileHeaderLen - int64(len(f.Name)+len(f.Extra))
	size := int64(fileHeaderLen+len(f.Name)+len(f.Extra)) + int64(f.CompressedSize64)
	if !skipDigests {
		if _, err := io.Copy(w, io.NewSectionReader(r, headerOffset, size)); err != nil {
			return 0, 0, err
		}
	}
	end := headerOffset + size
	if f.Flags&0x8 == 0 {
		return end, size, nil
	}
	// data descriptor is present. check whether it's 32 or 64 bits.
	dd := make([]byte, dataDescriptor64Len)
	if _, err := r.ReadAt(dd, end); err != nil {
		return 0, 0, err
	}
	if binary.LittleEndian.Uint32(dd) != dataDescriptorSignature {
		return 0, 0, errors.New("data descriptor signature is missing")
	}
	if binary.LittleEndian.Uint64(dd[16:]) == f.UncompressedSize64 {
		// 64 bit
	} else if binary.LittleEndian.Uint32(dd[12:]) == f.UncompressedSize {
		// 32 bit
		dd = dd[:dataDescriptorLen]
	}
	if !skipDigests {
		w.Write(dd)
	}
	size += int64(len(dd))
	end += int64(len(dd))
	return end, size, nil
}

func digestFileHeader(f *zip.File, r io.Reader, w io.Writer) (int64, error) {
	var fh zipCentralDir
	if err := binary.Read(r, binary.LittleEndian, &fh); err != nil {
		return 0, err
	}
	if fh.Signature != directoryHeaderSignature {
		return 0, errors.New("gap in zip file")
	}
	blob := make([]byte, int(fh.FilenameLen)+int(fh.ExtraLen)+int(fh.CommentLen))
	if _, err := r.Read(blob); err != nil {
		return 0, err
	}
	name := string(blob[:int(fh.FilenameLen)])
	if name != f.Name {
		return 0, errors.New("records out of order")
	}
	if name != appxSignature {
		binary.Write(w, binary.LittleEndian, fh)
		w.Write(blob)
	}
	return directoryHeaderLen + int64(len(blob)), nil
}

func digestDirEnd(r io.Reader, w io.Writer, dirStart, dirSize int64, nrec uint64) error {
	end64Start := dirStart + dirSize
	var end64 zip64End
	if err := binary.Read(r, binary.LittleEndian, &end64); err != nil {
		return err
	}
	if end64.Signature != directory64EndSignature {
		return errors.New("expected ZIP64 end record")
	}
	end64.DiskCDCount = nrec
	end64.TotalCDCount = nrec
	end64.CDSize = uint64(dirSize)
	end64.CDOffset = uint64(dirStart)
	binary.Write(w, binary.LittleEndian, end64)

	var end zipEndRecord
	if err := binary.Read(r, binary.LittleEndian, &end); err != nil {
		return err
	}
	if end.Signature64 != directory64LocSignature || end.Signature != directoryEndSignature {
		return errors.New("expected ZIP64 locator record")
	}
	end.Offset64 = uint64(end64Start)
	// non-ZIP64 fields are already set to their maximum
	binary.Write(w, binary.LittleEndian, end)
	return nil
}
