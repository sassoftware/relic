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

package comdoc

import (
	"bytes"
	"encoding/binary"
	"errors"
	"unicode/utf16"

	"github.com/sassoftware/relic/v7/lib/redblack"
)

// Parse the directory stream
func (r *ComDoc) readDir() error {
	var files []DirEnt
	count := r.SectorSize / 128
	raw := make([]RawDirEnt, count)
	cooked := make([]DirEnt, count)
	rootIndex := -1
	for sector := r.Header.DirNextSector; sector >= 0; sector = r.SAT[sector] {
		if err := r.readSectorStruct(sector, raw); err != nil {
			return err
		}
		for i, raw := range raw {
			cooked[i] = DirEnt{
				RawDirEnt: raw,
				Index:     len(files) + i,
				name:      raw.Name(),
			}
			if raw.Type == DirRoot {
				rootIndex = len(files) + i
			}
		}
		files = append(files, cooked...)
	}
	if rootIndex < 0 {
		return errors.New("missing root storage")
	}
	r.Files = files
	r.rootStorage = rootIndex
	rootFiles, err := r.ListDir(nil)
	if err != nil {
		return err
	}
	r.rootFiles = make([]int, 0, len(r.Files))
	for _, f := range rootFiles {
		r.rootFiles = append(r.rootFiles, f.Index)
	}
	return nil
}

// Return a pointer to the root storage.
func (r *ComDoc) RootStorage() *DirEnt {
	return &r.Files[r.rootStorage]
}

// List the items in a storage. If parent is nil, the root storage is used.
func (r *ComDoc) ListDir(parent *DirEnt) ([]*DirEnt, error) {
	if parent == nil {
		parent = r.RootStorage()
	}
	if parent.Type != DirRoot && parent.Type != DirStorage {
		return nil, errors.New("ListDir() on a non-directory object")
	}
	top := &r.Files[parent.StorageRoot]
	stack := []*DirEnt{top}
	var files []*DirEnt
	for len(stack) > 0 {
		i := len(stack) - 1
		item := stack[i]
		stack = stack[:i]
		files = append(files, item)
		if item.LeftChild != -1 {
			stack = append(stack, &r.Files[item.LeftChild])
		}
		if item.RightChild != -1 {
			stack = append(stack, &r.Files[item.RightChild])
		}
	}
	return files, nil
}

// Create a new stream and add it to the directory stream.
func (r *ComDoc) newDirEnt(name string, size uint32, sector SecID) (*DirEnt, error) {
	runes := utf16.Encode([]rune(name))
	runes = append(runes, 0)
	if len(runes) > 32 {
		return nil, errors.New("name is too long")
	}
	dirent := &DirEnt{
		RawDirEnt: RawDirEnt{
			NameLength:  uint16(2 * len(runes)),
			Type:        DirStream,
			LeftChild:   -1,
			RightChild:  -1,
			StorageRoot: -1,
			StreamSize:  size,
			NextSector:  sector,
		},
		Index: -1,
		name:  name,
	}
	copy(dirent.NameRunes[:], runes)
	dirent = r.appendDirEnt(dirent)
	return dirent, nil
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

// Rewrite the red-black tree on the root storage and write the directory
// stream to disk.
func (r *ComDoc) writeDirStream() error {
	// Presently there's no way to modify any storage other than the root one
	// so it's only needed to relabance that.
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
				chunk[k] = RawDirEnt{LeftChild: -1, RightChild: -1, StorageRoot: -1}
			}
		}
		buf.Reset()
		_ = binary.Write(buf, binary.LittleEndian, chunk)
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
	r.Header.DirSectorCount = uint32(len(freeList))
	return nil
}

// Rebuild the red-black directory tree of the root storage after files have
// been added or removed
func (r *ComDoc) rebuildTree(parent int, files []int) {
	tree := redblack.New(lessDirEnt)
	for _, i := range files {
		tree.Insert(&r.Files[i])
	}
	nodes := tree.Nodes()
	for _, n := range nodes {
		e := n.Item.(*DirEnt)
		if n == tree.Root {
			r.Files[parent].StorageRoot = int32(e.Index)
		}
		if n.Red {
			e.Color = Red
		} else {
			e.Color = Black
		}
		if n.Children[0] != nil {
			left := n.Children[0].Item.(*DirEnt)
			e.LeftChild = int32(left.Index)
		} else {
			e.LeftChild = -1
		}
		if n.Children[1] != nil {
			right := n.Children[1].Item.(*DirEnt)
			e.RightChild = int32(right.Index)
		} else {
			e.RightChild = -1
		}
	}
}

func lessDirEnt(i, j interface{}) bool {
	e, f := i.(*DirEnt), j.(*DirEnt)
	if e.NameLength != f.NameLength {
		return e.NameLength < f.NameLength
	}
	return e.name < f.name
}
