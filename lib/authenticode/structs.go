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
	"crypto/x509/pkix"
	"encoding/asn1"
	"io"
	"sort"
)

var (
	OidSpcIndirectDataContent = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 4}
	OidSpcSpOpusInfo          = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 12}
)

type SpcIndirectDataContent struct {
	Data          SpcAttributePeImageData
	MessageDigest DigestInfo
}

type SpcAttributePeImageData struct {
	Type  asn1.ObjectIdentifier
	Value SpcPeImageData `asn1:"explicit,optional,tag:0"`
}

type DigestInfo struct {
	DigestAlgorithm pkix.AlgorithmIdentifier
	Digest          []byte
}

type SpcPeImageData struct {
	Flags asn1.BitString
	File  asn1.RawValue
}

// file offsets to various interesting points in a PE file
type peMarkers struct {
	posOptHeader int64 // optional header
	posCksum     int64 // checksum field in optional header
	posDDCert    int64 // data directory entry for cert table
	posSecTbl    int64 // first section header
	posSections  int64 // first section data
	posAfterSec  int64 // after last section
	posCerts     int64 // cert blob
	posTrailer   int64 // everything after certs

	numSections int
	sizeOfOpt   int64
	sizeOfCerts int64
}

type peSection struct{ start, length int64 }
type peSectionList []peSection

func (s peSectionList) Len() int           { return len(s) }
func (s peSectionList) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }
func (s peSectionList) Less(i, j int) bool { return s[i].start < s[j].start }

type readerList struct {
	s peSectionList
}

func (l *readerList) Append(start, end int64) {
	length := end - start
	if length <= 0 {
		return
	}
	i := len(l.s) - 1
	if i >= 0 {
		// consolidate
		if l.s[i].start+l.s[i].length == start {
			l.s[i].length += length
			return
		}
	}
	l.s = append(l.s, peSection{start, length})
}

func (l *readerList) Reader(r io.ReaderAt) io.Reader {
	sort.Sort(l.s)
	readers := make([]io.Reader, len(l.s))
	for i, section := range l.s {
		readers[i] = io.NewSectionReader(r, section.start, section.length)
	}
	return io.MultiReader(readers...)
}
