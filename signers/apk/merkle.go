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

package apk

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"errors"

	"github.com/sassoftware/relic/v7/lib/zipslicer"
)

const merkleBlock = 1048576

// compute hashes of each 1MiB written
type merkleHasher struct {
	hashes []crypto.Hash
	blocks [][]byte
	buf    []byte
	n      int
	count  uint32
}

func newMerkleHasher(hashes []crypto.Hash) *merkleHasher {
	return &merkleHasher{
		buf:    make([]byte, merkleBlock),
		hashes: hashes,
		blocks: make([][]byte, len(hashes)),
	}
}

func (h *merkleHasher) block(block []byte) {
	var pref [5]byte
	pref[0] = 0xa5
	binary.LittleEndian.PutUint32(pref[1:], uint32(len(block)))
	for i, hash := range h.hashes {
		d := hash.New()
		d.Write(pref[:])
		d.Write(block)
		h.blocks[i] = d.Sum(h.blocks[i])
	}
	h.count++
}

func (h *merkleHasher) Write(d []byte) (int, error) {
	w := len(d)
	// completing previously buffered data
	if h.n != 0 && h.n+len(d) >= merkleBlock {
		n := h.n
		copy(h.buf[n:merkleBlock], d)
		d = d[merkleBlock-n:]
		h.block(h.buf)
		h.n = 0
	}
	// larger than a block -- hash it directly
	for len(d) >= merkleBlock {
		h.block(d[:merkleBlock])
		d = d[merkleBlock:]
	}
	// save the rest for later
	if len(d) != 0 {
		copy(h.buf[h.n:], d)
		h.n += len(d)
	}
	return w, nil
}

func (h *merkleHasher) flush() {
	if h.n != 0 {
		h.block(h.buf[:h.n])
		h.n = 0
	}
}

// after content is written, finish the digest by adding the central directory and end of directory
func (h *merkleHasher) Finish(inz *zipslicer.Directory, modified bool) ([][]byte, error) {
	// https://source.android.com/security/apksigning/v2#integrity-protected-contents
	// section 1: contents of zip entries (already written to hasher)
	h.flush()
	// section 2 is the signature block itself (not digested obviously)
	// section 3: central directory
	// TODO: zip64 support? android doesn't support it
	if inz.DirLoc >= (1 << 32) {
		return nil, errors.New("ZIP64 is not yet supported")
	}
	var cdirEntries, endOfDir []byte
	if modified {
		var b1, b2 bytes.Buffer
		if err := inz.WriteDirectory(&b1, &b2, false); err != nil {
			return nil, err
		}
		cdirEntries = b1.Bytes()
		endOfDir = b2.Bytes()
	} else {
		var err error
		cdirEntries, endOfDir, err = inz.GetOriginalDirectory(true)
		if err != nil {
			return nil, err
		}
	}
	_, _ = h.Write(cdirEntries)
	h.flush()
	// section 4: end of central directory
	_, _ = h.Write(endOfDir)
	h.flush()
	// compute final hash
	var pref [5]byte
	pref[0] = 0x5a
	binary.LittleEndian.PutUint32(pref[1:], h.count)
	ret := make([][]byte, len(h.hashes))
	for i, hash := range h.hashes {
		master := hash.New()
		master.Write(pref[:])
		master.Write(h.blocks[i])
		ret[i] = master.Sum(nil)
	}
	return ret, nil
}
