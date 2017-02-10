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
	"crypto"
	"debug/pe"
	"encoding/binary"
	"errors"
	"io"
	"io/ioutil"
)

// PE-COFF: https://www.microsoft.com/en-us/download/details.aspx?id=19509
// PE Authenticode: http://msdn.microsoft.com/en-us/windows/hardware/gg463180.aspx

// Calculate a digest (message imprint) over a PE image.
func DigestPE(r io.Reader, hash crypto.Hash) ([]byte, error) {
	d := hash.New()
	peStart, err := readDosHeader(r, d)
	if err != nil {
		return nil, err
	}
	if _, err := io.CopyN(d, r, peStart-96); err != nil {
		return nil, err
	}
	fh, err := readCoffHeader(r, d)
	if err != nil {
		return nil, err
	}
	secTblStart, sizeOfHdr, certStart, certSize, err := readOptHeader(r, d, peStart, fh)
	if err != nil {
		return nil, err
	}
	lastSection, err := readSections(r, d, fh, secTblStart, sizeOfHdr)
	if err != nil {
		return nil, err
	}
	if err := readTrailer(r, d, lastSection, certStart, certSize); err != nil {
		return nil, err
	}
	return d.Sum(nil), nil
}

func readDosHeader(r io.Reader, d io.Writer) (int64, error) {
	dosheader, err := readAndHash(r, d, 96)
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

func readOptHeader(r io.Reader, d io.Writer, peStart int64, fh *pe.FileHeader) (secTblStart, sizeOfHdr, certStart, certSize int64, err error) {
	buf := make([]byte, fh.SizeOfOptionalHeader)
	if _, err := r.Read(buf); err != nil {
		return 0, 0, 0, 0, err
	}
	// locate the bits that need to be omitted from hash
	cksumStart := 64
	cksumEnd := cksumStart + 4
	var dd4Start int64
	var dd pe.DataDirectory
	optMagic := binary.LittleEndian.Uint16(buf[:2])
	switch optMagic {
	case 0x10b:
		// PE32
		var opt pe.OptionalHeader32
		if err := binaryReadBytes(buf, &opt); err != nil {
			return 0, 0, 0, 0, err
		}
		if opt.NumberOfRvaAndSizes < 5 {
			return 0, 0, 0, 0, errors.New("PE header did not leave room for signature")
		} else {
			dd = opt.DataDirectory[4]
		}
		dd4Start = 128
		sizeOfHdr = int64(opt.SizeOfHeaders)
	case 0x20b:
		// PE32+
		var opt pe.OptionalHeader64
		if err := binaryReadBytes(buf, &opt); err != nil {
			return 0, 0, 0, 0, err
		}
		if opt.NumberOfRvaAndSizes < 5 {
			return 0, 0, 0, 0, errors.New("PE header did not leave room for signature")
		} else {
			dd = opt.DataDirectory[4]
		}
		dd4Start = 144
		sizeOfHdr = int64(opt.SizeOfHeaders)
	default:
		return 0, 0, 0, 0, errors.New("unrecognized optional header magic")
	}
	dd4End := dd4Start + 8
	certStart = int64(dd.VirtualAddress)
	certSize = int64(dd.Size)
	secTblStart = peStart + 24 + int64(fh.SizeOfOptionalHeader)
	d.Write(buf[:cksumStart])
	d.Write(buf[cksumEnd:dd4Start])
	d.Write(buf[dd4End:])
	return secTblStart, sizeOfHdr, certStart, certSize, nil
}

func readSections(r io.Reader, d io.Writer, fh *pe.FileHeader, secTblStart, sizeOfHdr int64) (int64, error) {
	secTblEnd := secTblStart + int64(40*fh.NumberOfSections)
	if secTblEnd > sizeOfHdr {
		return 0, errors.New("PE section overlaps section table")
	}
	nextSection := sizeOfHdr
	// assert that sections appear in-order
	for i := 0; i < int(fh.NumberOfSections); i++ {
		var sh pe.SectionHeader32
		if buf, err := readAndHash(r, d, 40); err != nil {
			return 0, err
		} else if err := binaryReadBytes(buf, &sh); err != nil {
			return 0, err
		}
		if sh.SizeOfRawData == 0 {
			continue
		}
		pos2 := int64(sh.PointerToRawData)
		if pos2 != nextSection {
			return 0, errors.New("PE sections are out of order or have gaps")
		}
		nextSection = pos2 + int64(sh.SizeOfRawData)
	}
	// hash the padding after the section table, then all section contents
	if _, err := io.CopyN(d, r, nextSection-secTblEnd); err != nil {
		return 0, err
	}
	return nextSection, nil
}

func readTrailer(r io.Reader, d io.Writer, lastSection, certStart, certSize int64) error {
	if certSize != 0 {
		if certStart < lastSection {
			return errors.New("Existing signature overlaps with PE sections")
		}
		if _, err := io.CopyN(d, r, certStart-lastSection); err != nil {
			return err
		}
		if _, err := io.CopyN(ioutil.Discard, r, certSize); err != nil {
			return err
		}
	}
	if _, err := io.Copy(d, r); err != nil && err != io.EOF {
		return err
	}
	return nil
}
