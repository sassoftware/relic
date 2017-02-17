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
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"unicode/utf16"

	"github.com/HuKeping/rbtree"
)

func (r *ComDoc) AddFile(name string, contents []byte) error {
	if r.writer == nil {
		return errors.New("file is not open for writing")
	}
	if err := r.DeleteFile(name); err != nil {
		return err
	}
	// store contents
	isShort := len(contents) < int(r.Header.MinStdStreamSize)
	nextSector, err := r.addStream(contents, isShort)
	if err != nil {
		return err
	}
	// create new dirent
	runes := utf16.Encode([]rune(name))
	runes = append(runes, 0)
	if len(runes) > 32 {
		return errors.New("name is too long")
	}
	dirent := &DirEnt{
		RawDirEnt: RawDirEnt{
			NameLength:  uint16(2 * len(runes)),
			Type:        DirStream,
			LeftChild:   -1,
			RightChild:  -1,
			StorageRoot: -1,
			StreamSize:  uint32(len(contents)),
			NextSector:  nextSector,
		},
		Index: -1,
		name:  name,
	}
	copy(dirent.NameRunes[:], runes)
	dirent = r.appendDirEnt(dirent)
	r.rootFiles = append(r.rootFiles, dirent.Index)
	r.changed = true
	return nil
}

func (r *ComDoc) DeleteFile(name string) error {
	keepFiles := make([]int, 0, len(r.rootFiles))
	for _, index := range r.rootFiles {
		item := &r.Files[index]
		if !strings.EqualFold(item.name, name) {
			keepFiles = append(keepFiles, index)
			continue
		}
		if item.Type != DirStream {
			return errors.New("can't delete or replace storages")
		}
		// free storage
		if item.StreamSize < r.Header.MinStdStreamSize {
			freeSectors(r.SSAT, item.NextSector)
		} else {
			freeSectors(r.SAT, item.NextSector)
		}
		// blank out the dirent
		*item = DirEnt{}
		r.changed = true
	}
	r.rootFiles = keepFiles
	return nil
}

func (r *ComDoc) Close() error {
	if !r.changed {
		if r.closer != nil {
			r.closer.Close()
			r.closer = nil
		}
		return nil
	}
	if err := r.writeShortSAT(); err != nil {
		return err
	}
	if err := r.writeDirStream(); err != nil {
		return err
	}
	// free sectors used by SAT or MSAT
	for i, j := range r.SAT {
		if j == SecIDSAT || j == SecIDMSAT {
			r.SAT[i] = SecIDFree
		}
	}
	// work out how many sectors are needed for SAT and MSAT
	var satList, msatList []SecID
	var satSectors, msatSectors int
	satPerSector := r.SectorSize / 4
	msatPerSector := satPerSector - 1
	for {
		if len(r.SAT)%satPerSector != 0 {
			panic("irregularly sized sector table")
		}
		satSectors = len(r.SAT) / satPerSector
		// 109 MSAT entries fit into the file header, the rest need more sectors
		msatSectors = (satSectors - msatInHeader + msatPerSector - 1) / msatPerSector
		// Check if there's room
		oldSize := len(r.SAT)
		freeList := r.makeFreeSectors(satSectors+msatSectors, false)
		if oldSize == len(r.SAT) {
			msatList = freeList[:msatSectors]
			satList = freeList[msatSectors:]
			break
		}
		// The SAT was extended so go around again to make sure that didn't
		// increase the requirements further
	}
	// Mark used sectors
	for _, i := range msatList {
		r.SAT[i] = SecIDMSAT
	}
	for _, i := range satList {
		r.SAT[i] = SecIDSAT
	}
	// Write out SAT
	buf := bytes.NewBuffer(r.sectorBuf)
	for i, sector := range satList {
		j := i * satPerSector
		buf.Reset()
		binary.Write(buf, binary.LittleEndian, r.SAT[j:j+satPerSector])
		if err := r.writeSector(sector, buf.Bytes()); err != nil {
			return err
		}
	}
	// Populate and write MSAT
	msatCount := msatInHeader + msatSectors*msatPerSector
	msat := make([]SecID, msatCount)
	copy(msat, satList)
	for i := len(satList); i < msatCount; i++ {
		msat[i] = SecIDFree
	}
	copy(r.Header.MSAT[:], msat)
	msat = msat[msatInHeader:] // done with the first 109
	nextSector := SecIDEndOfChain
	chunk := make([]SecID, satPerSector)
	for i := len(msatList) - 1; i >= 0; i-- { // each needs to link to the next, so walk backwards
		sector := msatList[i]
		j := i * msatPerSector
		copy(chunk, msat[j:])
		msat = msat[:j]
		chunk[msatPerSector] = nextSector
		nextSector = sector

		buf.Reset()
		binary.Write(buf, binary.LittleEndian, chunk)
		if err := r.writeSector(sector, buf.Bytes()); err != nil {
			return err
		}
	}
	r.Header.MSATNextSector = nextSector
	r.MSAT = msat
	// Write file header
	copy(r.Header.Magic[:], fileMagic)
	r.Header.ByteOrder = byteOrderMarker
	if r.Header.Revision != 0 && r.Header.Version != 0 {
		r.Header.Revision = 0x3e
		r.Header.Version = 0x3
	}
	r.Header.SATSectors = uint32(len(satList))
	r.Header.MSATSectorCount = uint32(len(msatList))
	buf.Reset()
	binary.Write(buf, binary.LittleEndian, r.Header)
	if _, err := r.writer.WriteAt(buf.Bytes(), 0); err != nil {
		return err
	}
	if r.closer != nil {
		r.closer.Close()
		r.closer = nil
	}
	return nil
}

func freeSectors(sat []SecID, sector SecID) {
	for {
		nextSector := sat[sector]
		sat[sector] = SecIDFree
		if nextSector < 0 {
			break
		}
		sector = nextSector
	}
}

// Store a blob as a chain of sectors and return the first sector ID
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

// Return a list of "count" free sectors or short sectors, extending the table if needed
func (r *ComDoc) makeFreeSectors(count int, short bool) []SecID {
	if count <= 0 {
		return nil
	}
	freeList := make([]SecID, 0, count)
	var sat []SecID
	if short {
		sat = r.SSAT
	} else {
		sat = r.SAT
	}
	// scan for existing free sectors
	for i, j := range sat {
		if j != SecIDFree {
			continue
		}
		freeList = append(freeList, SecID(i))
		count--
		if count == 0 {
			return freeList
		}
	}
	// extend the sector table
	sectorsPerBlock := r.SectorSize / 4
	needBlocks := (count + sectorsPerBlock - 1) / sectorsPerBlock
	oldCount := len(sat)
	newSAT := append(sat, make([]SecID, needBlocks*sectorsPerBlock)...)
	for i := oldCount; i < len(newSAT); i++ {
		newSAT[i] = SecIDFree
		if count > 0 {
			freeList = append(freeList, SecID(i))
			count--
		}
	}
	if short {
		r.SSAT = newSAT
	} else {
		r.SAT = newSAT
	}
	return freeList
}

func (r *ComDoc) writeSector(sector SecID, content []byte) error {
	if len(content) > r.SectorSize {
		panic("excessive write")
	} else if len(content) < r.SectorSize {
		buf := r.sectorBuf
		copy(buf, content)
		for i := len(content); i < r.SectorSize; i++ {
			buf[i] = 0
		}
		content = buf[:r.SectorSize]
	}
	_, err := r.writer.WriteAt(content, r.sectorToOffset(sector))
	return err
}

func (r *ComDoc) writeShortSector(shortSector SecID, content []byte) error {
	if len(content) > r.ShortSectorSize {
		panic("excessive write")
	} else if len(content) < r.ShortSectorSize {
		buf := r.sectorBuf
		copy(buf, content)
		for i := len(content); i < r.ShortSectorSize; i++ {
			buf[i] = 0
		}
		content = buf[:r.ShortSectorSize]
	}
	// walk the short stream to find the big sector that holds the target small sector
	bigSectorIndex := int(shortSector) * r.ShortSectorSize / r.SectorSize
	offset := int(shortSector)*r.ShortSectorSize - bigSectorIndex*r.SectorSize
	root := &r.Files[r.rootStorage]
	bigSectorId := root.NextSector
	for ; bigSectorIndex > 0; bigSectorIndex-- {
		next := r.SAT[bigSectorId]
		if next < 0 {
			break
		}
		bigSectorId = next
	}
	if bigSectorIndex > 0 {
		// extend short sector stream
		freeList := r.makeFreeSectors(bigSectorIndex, false)
		for _, sector := range freeList {
			r.SAT[bigSectorId] = sector
			bigSectorId = sector
		}
		r.SAT[bigSectorId] = SecIDEndOfChain
	}
	n := r.sectorToOffset(bigSectorId) + int64(offset)
	if _, err := r.writer.WriteAt(content, n); err != nil {
		return err
	}
	streamLength := uint32(int(shortSector+1) * r.ShortSectorSize)
	if streamLength > root.StreamSize {
		root.StreamSize = streamLength
	}
	return nil
}

// Add a DirEnt to the directory stream, extending it if necessary
func (r *ComDoc) appendDirEnt(dirent *DirEnt) *DirEnt {
	// look for a free slot
	index := -1
	for i, j := range r.Files {
		if j.Type == DirEmpty {
			index = i
			break
		}
	}
	if index < 0 {
		// extend the dir stream
		index = len(r.Files)
		newDirs := make([]DirEnt, r.SectorSize/128)
		r.Files = append(r.Files, newDirs...)
	}
	r.Files[index] = *dirent
	r.Files[index].Index = index
	return &r.Files[index]
}

// Rebuild the red-black tree of directory entries
func (r *ComDoc) rebuildTree(parent int, files []int) {
	rbt := rbtree.New()
	for _, i := range files {
		f := &r.Files[i]
		rbt.Insert(f)
	}
	stack := []*rbtree.Node{rbt.Root}
	for len(stack) > 0 {
		i := len(stack) - 1
		node := stack[i]
		stack = stack[:i]
		f := node.Item.(*DirEnt)
		f.RedIsBlack = uint8(node.Color)
		if node.Left != rbt.NIL {
			stack = append(stack, node.Left)
			left := node.Left.Item.(*DirEnt)
			f.LeftChild = int32(left.Index)
		} else {
			f.LeftChild = -1
		}
		if node.Right != rbt.NIL {
			stack = append(stack, node.Right)
			right := node.Right.Item.(*DirEnt)
			f.RightChild = int32(right.Index)
		} else {
			f.RightChild = -1
		}
	}
	rootFile := rbt.Root.Item.(*DirEnt)
	r.Files[parent].StorageRoot = int32(rootFile.Index)
}

func (e *DirEnt) Less(i rbtree.Item) bool {
	f := i.(*DirEnt)
	if e.NameLength != f.NameLength {
		return e.NameLength < f.NameLength
	}
	return e.name < f.name
}

func (r *ComDoc) writeShortSAT() error {
	freeSectors(r.SAT, r.Header.SSATNextSector)
	perSector := r.SectorSize / 4
	if len(r.SSAT)%perSector != 0 {
		panic("irregularly sized SSAT")
	}
	freeList := r.makeFreeSectors(len(r.SSAT)/perSector, false)
	buf := bytes.NewBuffer(r.sectorBuf)
	first := SecIDEndOfChain
	previous := first
	for i, sector := range freeList {
		j := i * perSector
		chunk := r.SSAT[j : j+perSector]
		buf.Reset()
		binary.Write(buf, binary.LittleEndian, chunk)
		if err := r.writeSector(sector, buf.Bytes()); err != nil {
			return err
		}
		if previous == SecIDEndOfChain {
			first = sector
		} else {
			r.SAT[previous] = sector
		}
		previous = sector
	}
	r.SAT[previous] = SecIDEndOfChain
	r.Header.SSATNextSector = first
	r.Header.SSATSectorCount = uint32(len(freeList))
	return nil
}

func (r *ComDoc) writeDirStream() error {
	r.rebuildTree(r.rootStorage, r.rootFiles)
	freeSectors(r.SAT, r.Header.DirNextSector)
	perSector := r.SectorSize / 128
	if len(r.Files)%perSector != 0 {
		panic("irregularly sized directory stream")
	}
	freeList := r.makeFreeSectors(len(r.Files)/perSector, false)
	chunk := make([]RawDirEnt, perSector)
	buf := bytes.NewBuffer(r.sectorBuf)
	first := SecIDEndOfChain
	previous := first
	for i, sector := range freeList {
		j := i * perSector
		for k, f := range r.Files[j : j+perSector] {
			if f.Type != DirEmpty {
				chunk[k] = f.RawDirEnt
			} else {
				chunk[k] = RawDirEnt{}
			}
		}
		buf.Reset()
		binary.Write(buf, binary.LittleEndian, chunk)
		if err := r.writeSector(sector, buf.Bytes()); err != nil {
			return err
		}
		if previous == SecIDEndOfChain {
			first = sector
		} else {
			r.SAT[previous] = sector
		}
		previous = sector
	}
	r.SAT[previous] = SecIDEndOfChain
	r.Header.DirNextSector = first
	return nil
}
