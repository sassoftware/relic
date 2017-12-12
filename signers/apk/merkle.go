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
	"io"

	"github.com/pkg/errors"
	"github.com/sassoftware/relic/lib/zipslicer"
)

func merkleDigest(r io.ReaderAt, inz *zipslicer.Directory, hash crypto.Hash) ([]byte, error) {
	lastFile := inz.File[len(inz.File)-1]
	lastSize, _ := lastFile.GetTotalSize()
	sigLoc := int64(lastFile.Offset) + lastSize
	// https://source.android.com/security/apksigning/v2#integrity-protected-contents
	// section 1: contents of zip entries
	blocks, err := merkleBlocks(nil, io.NewSectionReader(r, 0, sigLoc), sigLoc, hash)
	if err != nil {
		return nil, err
	}
	// section 2 is the signature block itself (not digested obviously)
	// section 3: central directory
	// TODO: zip64 support
	if inz.DirLoc >= (1 << 32) {
		return nil, errors.New("ZIP64 is not yet supported")
	}
	cdir := make([]byte, inz.Size-inz.DirLoc)
	if _, err := io.ReadFull(io.NewSectionReader(r, inz.DirLoc, inz.Size-inz.DirLoc), cdir); err != nil {
		return nil, err
	}
	endOfDir := cdir[len(cdir)-directoryEndLen:]
	cdirEntries := cdir[:len(cdir)-directoryEndLen]
	if binary.LittleEndian.Uint32(endOfDir) != directoryEndSignature {
		return nil, errors.New("zip file with comment not supported")
	}
	blocks, err = merkleBlocks(blocks, bytes.NewReader(cdirEntries), int64(len(cdirEntries)), hash)
	if err != nil {
		return nil, err
	}
	// section 4: end of central directory
	// modify the offset so as to omit the effect of the signature being inserted
	binary.LittleEndian.PutUint32(endOfDir[16:], uint32(sigLoc))
	blocks, err = merkleBlocks(blocks, bytes.NewReader(endOfDir), int64(len(endOfDir)), hash)
	if err != nil {
		return nil, err
	}
	var pref [5]byte
	pref[0] = 0x5a
	binary.LittleEndian.PutUint32(pref[1:], uint32(len(blocks)/hash.Size()))
	master := hash.New()
	master.Write(pref[:])
	master.Write(blocks)
	return master.Sum(nil), nil
}

// read up to size bytes from r, and for each 1MiB compute a digest and append it to blocks
func merkleBlocks(blocks []byte, r io.Reader, size int64, hash crypto.Hash) ([]byte, error) {
	for ; size > 0; size -= 1048576 {
		chunk := size
		if chunk > 1048576 {
			chunk = 1048576
		}
		var pref [5]byte
		pref[0] = 0xa5
		binary.LittleEndian.PutUint32(pref[1:], uint32(chunk))
		d := hash.New()
		d.Write(pref[:])
		if _, err := io.CopyN(d, r, chunk); err != nil {
			return nil, err
		}
		blocks = d.Sum(blocks)
	}
	return blocks, nil
}
