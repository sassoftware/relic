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

package authenticode

import (
	"bytes"
	"crypto"
	"debug/pe"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
)

// PE-COFF: https://www.microsoft.com/en-us/download/details.aspx?id=19509
// PE Authenticode: http://msdn.microsoft.com/en-us/windows/hardware/gg463180.aspx

type PEDigest struct {
	OrigSize   int64
	CertStart  int64
	Imprint    []byte
	PageHashes []byte
	Hash       crypto.Hash
	markers    *peHeaderValues
}

const dosHeaderSize = 64

// Calculate a digest (message imprint) over a PE image. Returns a structure
// that can be used to sign the imprint and produce a binary patch to apply the
// signature.
func DigestPE(r io.Reader, hash crypto.Hash, doPageHash bool) (*PEDigest, error) {
	// Read and buffer all the headers
	buf := bytes.NewBuffer(make([]byte, 0, 4096))
	peStart, err := readDosHeader(r, buf)
	if err != nil {
		return nil, err
	}
	if _, err := io.CopyN(buf, r, peStart-dosHeaderSize); err != nil {
		return nil, err
	}
	fh, err := readCoffHeader(r, buf)
	if err != nil {
		return nil, err
	}
	hvals, err := readOptHeader(r, buf, peStart, fh)
	if err != nil {
		return nil, err
	}
	sections, err := readSections(r, buf, fh, hvals)
	if err != nil {
		return nil, err
	}
	digester := setupDigester(hash, buf.Bytes(), hvals, sections, doPageHash)
	// Hash sections
	nextSection := hvals.sizeOfHdr
	for i, sh := range sections {
		if sh.SizeOfRawData == 0 {
			continue
		}
		if int64(sh.PointerToRawData) != nextSection {
			return nil, fmt.Errorf("PE section %d begins at 0x%x but expected 0x%x", i, sh.PointerToRawData, nextSection)
		}
		if err := digester.section(r, sh); err != nil {
			return nil, err
		}
		nextSection += int64(sh.SizeOfRawData)
	}
	// Hash trailer after the sections and cert table
	origSize, err := readTrailer(r, digester.imageDigest, nextSection, hvals.certStart, hvals.certSize)
	if err != nil {
		return nil, err
	}
	certStart := origSize
	if n := origSize % 8; n != 0 {
		// pad to 8 bytes
		padding := 8 - n
		digester.imageDigest.Write(make([]byte, padding))
		certStart += padding
	}
	imprint, pagehashes, err := digester.finish()
	if err != nil {
		return nil, err
	}
	return &PEDigest{origSize, certStart, imprint, pagehashes, hash, hvals}, nil
}

type imageHasher struct {
	hashFunc    crypto.Hash
	imageDigest hash.Hash
	pageHashes  []byte
	zeroPage    []byte
	pageBuf     []byte
	doPageHash  bool
	lastPage    uint32
}

func setupDigester(hash crypto.Hash, header []byte, hvals *peHeaderValues, sections []pe.SectionHeader32, doPageHash bool) *imageHasher {
	imageDigest := hash.New()
	imageDigest.Write(header)
	h := &imageHasher{hashFunc: hash, imageDigest: imageDigest, doPageHash: doPageHash}
	if doPageHash {
		h.zeroPage = make([]byte, hvals.pageSize) // full page of zeroes, for padding
		h.pageBuf = make([]byte, hvals.pageSize)  // scratch space
		// make space for all the page hashes
		pages := 2
		for _, sh := range sections {
			spage := (sh.SizeOfRawData + hvals.pageSize - 1) / hvals.pageSize
			pages += int(spage)
		}
		h.pageHashes = make([]byte, 0, pages*(4+hash.Size()))
		// the first page is the headers padded out to a full page with the
		// signature bits snipped out in the same way as for the regular
		// imprint. the padding is done based on the full size of the
		// header, so the data being hashed is 12 bytes short of a full
		// page
		removed := int(hvals.sizeOfHdr) - len(header)
		h.addPageHash(0, header, removed)
	}
	return h
}

func (h *imageHasher) section(r io.Reader, sh pe.SectionHeader32) error {
	if !h.doPageHash {
		_, err := io.CopyN(h.imageDigest, r, int64(sh.SizeOfRawData))
		return err
	}
	position := sh.PointerToRawData
	remaining := int(sh.SizeOfRawData)
	for remaining > 0 {
		n := remaining
		if n > len(h.pageBuf) {
			n = len(h.pageBuf)
		}
		buf := h.pageBuf[:n]
		if _, err := io.ReadFull(r, buf); err != nil {
			return err
		}
		h.imageDigest.Write(buf)
		h.addPageHash(position, buf, 0)
		position += uint32(n)
		remaining -= n
		h.lastPage = position
	}
	return nil
}

func (h *imageHasher) finish() ([]byte, []byte, error) {
	sum := h.imageDigest.Sum(nil)
	if h.doPageHash {
		h.addPageHash(h.lastPage, nil, 0)
	}
	return sum, h.pageHashes, nil
}

func (h *imageHasher) addPageHash(offset uint32, blob []byte, removed int) {
	var obytes [4]byte
	binary.LittleEndian.PutUint32(obytes[:], offset)
	h.pageHashes = append(h.pageHashes, obytes[:]...)
	if len(blob) == 0 {
		// last "page" has a null digest
		h.pageHashes = append(h.pageHashes, make([]byte, h.hashFunc.Size())...)
		return
	}
	d := h.hashFunc.New()
	d.Write(blob)
	needzero := len(h.zeroPage) - len(blob) - removed
	d.Write(h.zeroPage[:needzero])
	h.pageHashes = d.Sum(h.pageHashes)
}

func readDosHeader(r io.Reader, d io.Writer) (int64, error) {
	dosheader, err := readAndHash(r, d, dosHeaderSize)
	if err != nil {
		return 0, err
	} else if dosheader[0] != 'M' || dosheader[1] != 'Z' {
		return 0, errors.New("not a PE file")
	}
	return int64(binary.LittleEndian.Uint32(dosheader[0x3c:])), nil
}

func readCoffHeader(r io.Reader, d io.Writer) (*pe.FileHeader, error) {
	if magic, err := readAndHash(r, d, 4); err != nil {
		return nil, err
	} else if magic[0] != 'P' || magic[1] != 'E' || magic[2] != 0 || magic[3] != 0 {
		return nil, errors.New("not a PE file")
	}

	buf, err := readAndHash(r, d, 20)
	if err != nil {
		return nil, err
	}
	hdr := new(pe.FileHeader)
	if err := binaryReadBytes(buf, hdr); err != nil {
		return nil, err
	}
	return hdr, nil
}

const (
	// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#optional-header-image-only
	optHeaderMagicPE32     = 0x10b
	optHeaderMagicPE32Plus = 0x20b

	// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#machine-types
	imageFileMachineAlpha   = 0x184
	imageFileMachineAlpha64 = 0x284
)

func readOptHeader(r io.Reader, d io.Writer, peStart int64, fh *pe.FileHeader) (*peHeaderValues, error) {
	hvals := new(peHeaderValues)
	hvals.peStart = peStart
	// https://devblogs.microsoft.com/oldnewthing/20210510-00/
	switch fh.Machine {
	case pe.IMAGE_FILE_MACHINE_IA64, imageFileMachineAlpha, imageFileMachineAlpha64:
		hvals.pageSize = 8192
	default:
		hvals.pageSize = 4096
	}
	buf := make([]byte, fh.SizeOfOptionalHeader)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	// locate the bits that need to be omitted from hash
	cksumStart := 64
	cksumEnd := cksumStart + 4
	var dd4Start int64
	var dd pe.DataDirectory
	optMagic := binary.LittleEndian.Uint16(buf[:2])
	switch optMagic {
	case optHeaderMagicPE32:
		// PE32
		var opt pe.OptionalHeader32
		if err := binaryReadBytes(buf, &opt); err != nil {
			return nil, err
		}
		if opt.NumberOfRvaAndSizes < 5 {
			return nil, errors.New("PE header did not leave room for signature")
		}
		dd = opt.DataDirectory[4]
		dd4Start = 128
		hvals.sizeOfHdr = int64(opt.SizeOfHeaders)
		hvals.fileAlign = opt.FileAlignment
	case optHeaderMagicPE32Plus:
		// PE32+
		var opt pe.OptionalHeader64
		if err := binaryReadBytes(buf, &opt); err != nil {
			return nil, err
		}
		if opt.NumberOfRvaAndSizes < 5 {
			return nil, errors.New("PE header did not leave room for signature")
		}
		dd = opt.DataDirectory[4]
		dd4Start = 144
		hvals.sizeOfHdr = int64(opt.SizeOfHeaders)
		hvals.fileAlign = opt.FileAlignment
	default:
		return nil, errors.New("unrecognized optional header magic")
	}
	dd4End := dd4Start + 8
	hvals.certStart = int64(dd.VirtualAddress)
	hvals.certSize = int64(dd.Size)
	hvals.secTblStart = peStart + 24 + int64(fh.SizeOfOptionalHeader)
	_, _ = d.Write(buf[:cksumStart])
	_, _ = d.Write(buf[cksumEnd:dd4Start])
	_, _ = d.Write(buf[dd4End:])
	hvals.posDDCert = peStart + 24 + dd4Start
	return hvals, nil
}

func readSections(r io.Reader, d io.Writer, fh *pe.FileHeader, hvals *peHeaderValues) ([]pe.SectionHeader32, error) {
	// read and hash section table
	sections := make([]pe.SectionHeader32, fh.NumberOfSections)
	size := int(fh.NumberOfSections) * 40
	secTblEnd := hvals.secTblStart + int64(size)
	if secTblEnd > hvals.sizeOfHdr {
		return nil, errors.New("PE section overlaps section table")
	}
	if buf, err := readAndHash(r, d, size); err != nil {
		return nil, err
	} else if err := binaryReadBytes(buf, sections); err != nil {
		return nil, err
	}
	// look for start of first section and check for overlap
	for i, section := range sections {
		if section.SizeOfRawData == 0 {
			continue
		}
		if p := int64(section.PointerToRawData); p < secTblEnd {
			return nil, fmt.Errorf("PE section %d at 0x%x overlaps section table at 0x%x", i, p, secTblEnd)
		} else if p < hvals.sizeOfHdr {
			// some samples have a SizeOfHeaders that goes past the start of the first section
			hvals.sizeOfHdr = p
		}
		// Adjust any sections that are not properly aligned
		sections[i].SizeOfRawData = align32(section.SizeOfRawData, hvals.fileAlign)
	}
	// hash the padding after the section table
	if _, err := io.CopyN(d, r, hvals.sizeOfHdr-secTblEnd); err != nil {
		return nil, err
	}
	return sections, nil
}

func readTrailer(r io.Reader, d io.Writer, lastSection, certStart, certSize int64) (int64, error) {
	if certSize == 0 {
		n, err := io.Copy(d, r)
		return lastSection + n, err
	}
	if certStart < lastSection {
		return 0, errors.New("existing signature overlaps with PE sections")
	}
	if _, err := io.CopyN(d, r, certStart-lastSection); err != nil {
		return 0, err
	}
	if _, err := io.CopyN(ioutil.Discard, r, certSize); err != nil {
		return 0, err
	}
	if n, _ := io.Copy(ioutil.Discard, r); n > 0 {
		return 0, errors.New("trailing garbage after existing certificate")
	}
	return certStart, nil
}

type peHeaderValues struct {
	// start of PE header
	peStart int64
	// file offset to the data directory entry for the cert table, in the optional header
	posDDCert int64
	// file offset to the end of the optional header and the start of the section table
	secTblStart int64
	// size of all headers plus padding
	sizeOfHdr int64
	// architecture page size
	pageSize uint32
	// section alignment in file
	fileAlign uint32
	// file offset and size of the certificate table
	certStart, certSize int64
}
