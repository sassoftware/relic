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

package zipslicer

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
)

type Directory struct {
	File   []*File
	Size   int64
	DirLoc int64
	r      io.ReaderAt
	end64  zip64End
	loc64  zip64Loc
	end    zipEndRecord
}

// Return the offset of the zip central directory
func FindDirectory(r io.ReaderAt, size int64) (int64, error) {
	pos := size - directoryEndLen - directory64LocLen
	var endb [directoryEndLen + directory64LocLen]byte
	if _, err := r.ReadAt(endb[:], pos); err != nil {
		return 0, err
	}
	re := bytes.NewReader(endb[:])
	var loc64 zip64Loc
	var end zipEndRecord
	binary.Read(re, binary.LittleEndian, &loc64)
	binary.Read(re, binary.LittleEndian, &end)
	if end.Signature != directoryEndSignature {
		return 0, errors.New("zip central directory not found")
	}
	if end.TotalCDCount == uint16Max || end.CDSize == uint32Max || end.CDOffset == uint32Max {
		if loc64.Signature != directory64LocSignature {
			return 0, errors.New("expected ZIP64 locator")
		}
		// ZIP64
		var end64b [directory64EndLen]byte
		if _, err := r.ReadAt(end64b[:], int64(loc64.Offset)); err != nil {
			return 0, err
		}
		var end64 zip64End
		binary.Read(bytes.NewReader(end64b[:]), binary.LittleEndian, &end64)
		if end64.Signature != directory64EndSignature {
			return 0, errors.New("zip central directory not found")
		}
		return int64(end64.CDOffset), nil
	}
	return int64(end.CDOffset), nil
}

func ReadWithDirectory(r io.ReaderAt, size int64, cd []byte) (*Directory, error) {
	files := make([]*File, 0)
	for {
		if binary.LittleEndian.Uint32(cd) != directoryHeaderSignature {
			break
		}
		var hdr zipCentralDir
		binary.Read(bytes.NewReader(cd), binary.LittleEndian, &hdr)
		f := &File{
			CreatorVersion:   hdr.CreatorVersion,
			ReaderVersion:    hdr.ReaderVersion,
			Flags:            hdr.Flags,
			Method:           hdr.Method,
			ModifiedTime:     hdr.ModifiedTime,
			ModifiedDate:     hdr.ModifiedDate,
			CRC32:            hdr.CRC32,
			CompressedSize:   uint64(hdr.CompressedSize),
			UncompressedSize: uint64(hdr.UncompressedSize),
			InternalAttrs:    hdr.InternalAttrs,
			ExternalAttrs:    hdr.ExternalAttrs,
			Offset:           uint64(hdr.Offset),

			r:  r,
			rs: size,
		}
		f.raw = make([]byte, directoryHeaderLen+int(hdr.FilenameLen)+int(hdr.ExtraLen)+int(hdr.CommentLen))
		copy(f.raw, cd)
		cd = cd[directoryHeaderLen:]
		f.Name, cd = string(cd[:int(hdr.FilenameLen)]), cd[int(hdr.FilenameLen):]
		f.Extra, cd = cd[:int(hdr.ExtraLen)], cd[int(hdr.ExtraLen):]
		f.Comment, cd = cd[:int(hdr.CommentLen)], cd[int(hdr.CommentLen):]
		needUSize := f.UncompressedSize == uint32Max
		needCSize := f.CompressedSize == uint32Max
		needOffset := f.Offset == uint32Max
		extra := f.Extra
		for len(extra) >= 4 {
			tag := binary.LittleEndian.Uint16(extra[:2])
			size := binary.LittleEndian.Uint16(extra[2:4])
			if int(size) > len(extra)-4 {
				break
			}
			if tag == zip64ExtraId {
				e := extra[4 : 4+size]
				if needUSize && size >= 8 {
					f.UncompressedSize = binary.LittleEndian.Uint64(e)
					needUSize = false
				}
				if needCSize && size >= 16 {
					f.CompressedSize = binary.LittleEndian.Uint64(e[8:])
					needCSize = false
				}
				if needOffset && size >= 24 {
					f.Offset = binary.LittleEndian.Uint64(e[16:])
					needOffset = false
				}
				break
			}
			extra = extra[4+size:]
		}
		if needCSize || needOffset {
			return nil, errors.New("missing ZIP64 header")
		}
		files = append(files, f)
	}
	d := &Directory{
		File:   files,
		Size:   size,
		DirLoc: size - int64(len(cd)),
		r:      r,
	}
	rd := bytes.NewReader(cd)
	switch binary.LittleEndian.Uint32(cd) {
	case directory64EndSignature:
		binary.Read(rd, binary.LittleEndian, &d.end64)
		binary.Read(rd, binary.LittleEndian, &d.loc64)
	case directoryEndSignature:
	default:
		return nil, errors.New("expected end record")
	}
	binary.Read(rd, binary.LittleEndian, &d.end)
	return d, nil
}

func Read(r io.ReaderAt, size int64) (*Directory, error) {
	loc, err := FindDirectory(r, size)
	if err != nil {
		return nil, err
	}
	cd := make([]byte, size-loc)
	if _, err := r.ReadAt(cd, loc); err != nil {
		return nil, err
	}
	return ReadWithDirectory(r, size, cd)
}

func ReadStream(r io.Reader, size int64, cd []byte) (*Directory, error) {
	ra := &streamReaderAt{r: r}
	return ReadWithDirectory(ra, size, cd)
}

func (d *Directory) Truncate(n int, body, dir io.Writer) error {
	if body != nil {
		for i := 0; i < n; i++ {
			f := d.File[i]
			fs, err := f.GetTotalSize()
			if err != nil {
				return err
			}
			if _, err := io.Copy(body, io.NewSectionReader(d.r, int64(f.Offset), fs)); err != nil {
				return err
			}
		}
	}
	cdOffset := d.File[n].Offset
	var size uint64
	for i := 0; i < n; i++ {
		blob, err := d.File[i].GetDirectoryHeader()
		if err != nil {
			return err
		}
		dir.Write(blob)
		size += uint64(len(blob))
	}
	end := d.end
	if d.end64.Signature != 0 {
		end64 := d.end64
		end64.DiskCDCount = uint64(n)
		end64.TotalCDCount = uint64(n)
		end64.CDSize = size
		end64.CDOffset = cdOffset
		binary.Write(dir, binary.LittleEndian, end64)
		loc := d.loc64
		loc.Offset = cdOffset + size
		binary.Write(dir, binary.LittleEndian, loc)
	} else {
		if cdOffset >= uint32Max || n >= uint16Max {
			return errors.New("file too big for 32-bit ZIP")
		}
		end.DiskCDCount = uint16(n)
		end.TotalCDCount = uint16(n)
		end.CDSize = uint32(size)
		end.CDOffset = uint32(cdOffset)
	}
	binary.Write(dir, binary.LittleEndian, end)
	return nil
}

func (d *Directory) WriteDirectory(w io.Writer) error {
	buf := bufio.NewWriter(w)
	cdoff := d.DirLoc
	var count, size uint64
	for _, f := range d.File {
		blob, err := f.GetDirectoryHeader()
		if err != nil {
			return err
		}
		if _, err := buf.Write(blob); err != nil {
			return err
		}
		count++
		size += uint64(len(blob))
	}
	end64off := cdoff + int64(size)
	end64 := zip64End{
		Signature:      directory64EndSignature,
		RecordSize:     directory64EndLen - 12,
		CreatorVersion: zip45,
		ReaderVersion:  zip45,
		DiskCDCount:    count,
		TotalCDCount:   count,
		CDSize:         size,
		CDOffset:       uint64(cdoff),
	}
	if err := binary.Write(buf, binary.LittleEndian, end64); err != nil {
		return err
	}
	loc64 := zip64Loc{
		Signature: directory64LocSignature,
		Offset:    uint64(end64off),
		DiskCount: 1,
	}
	if err := binary.Write(buf, binary.LittleEndian, loc64); err != nil {
		return err
	}
	end := zipEndRecord{
		Signature:    directoryEndSignature,
		DiskCDCount:  uint16Max,
		TotalCDCount: uint16Max,
		CDSize:       uint32Max,
		CDOffset:     uint32Max,
	}
	if err := binary.Write(buf, binary.LittleEndian, end); err != nil {
		return err
	}
	return buf.Flush()
}

type streamReaderAt struct {
	r   io.Reader
	pos int64
}

func (r *streamReaderAt) ReadAt(d []byte, p int64) (int, error) {
	if p > r.pos {
		if _, err := io.CopyN(ioutil.Discard, r.r, p-r.pos); err != nil {
			return 0, err
		}
		r.pos = p
	} else if p < r.pos {
		return 0, fmt.Errorf("attempted to seek backwards: at %d, to %d", r.pos, p)
	}
	n, err := r.r.Read(d)
	r.pos += int64(n)
	return n, err
}

func (d *Directory) AddFile(f *File) (*File, error) {
	size, err := f.GetTotalSize()
	if err != nil {
		return nil, err
	}
	f.Offset = uint64(d.DirLoc)
	d.DirLoc += size
	d.File = append(d.File, f)
	return f, nil
}
