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

package binpatch

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"

	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/atomicfile"
)

type PatchInfo struct {
	PatchOffset int64 `json:"patch_offset,omitempty"`
	PatchLength int64 `json:"patch_length,omitempty"`

	Data map[string]interface{} `json:"data"`

	Patch []byte `json:"-"`
}

func New(blob []byte, offset, length int64, data map[string]interface{}) *PatchInfo {
	return &PatchInfo{offset, length, data, blob}
}

func Load(blob []byte) (*PatchInfo, error) {
	idx := bytes.IndexByte(blob, 0)
	if idx < 0 {
		return nil, errors.New("Did not find null terminator in patch")
	}
	info := new(PatchInfo)
	if err := json.Unmarshal(blob[:idx], info); err != nil {
		return nil, err
	}
	info.Patch = blob[idx+1:]
	return info, nil
}

func (p *PatchInfo) Dump() []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.Encode(p)
	buf.WriteByte(0)
	buf.Write(p.Patch)
	return buf.Bytes()
}

func (p *PatchInfo) Apply(infile *os.File, outpath string) error {
	ininfo, err := infile.Stat()
	if err != nil {
		return err
	}
	if outpath == "-" {
		// send to stdout
		return p.apply(infile, os.Stdout)
	} else if outpath == "" {
		outpath = infile.Name()
	}
	newEnd := p.PatchOffset + int64(len(p.Patch))
	oldEnd := p.PatchOffset + p.PatchLength
	outinfo, err := os.Lstat(outpath)
	if err == nil && canOverwrite(ininfo, outinfo) && (p.PatchLength == int64(len(p.Patch)) || newEnd >= ininfo.Size() || oldEnd == ininfo.Size()) {
		return p.applyInPlace(infile, ininfo.Size())
	}
	// write-rename
	out, err := atomicfile.New(outpath)
	if err != nil {
		return err
	}
	defer out.Close()
	if err := p.apply(infile, out); err != nil {
		return err
	}
	if err := out.Commit(); err != nil {
		return err
	}
	return nil
}

func (p *PatchInfo) apply(infile io.ReadSeeker, outstream io.Writer) error {
	if _, err := infile.Seek(0, 0); err != nil {
		return err
	}
	if p.PatchOffset > 0 {
		if _, err := io.CopyN(outstream, infile, p.PatchOffset); err != nil {
			return err
		}
	}
	if n, err := outstream.Write(p.Patch); err != nil {
		return err
	} else if n != len(p.Patch) {
		return io.ErrShortWrite
	}
	if _, err := infile.Seek(p.PatchOffset+p.PatchLength, 0); err != nil {
		return err
	}
	_, err := io.Copy(outstream, infile)
	return err
}

func (p *PatchInfo) applyInPlace(outfile *os.File, oldSize int64) error {
	_, err := outfile.WriteAt(p.Patch, p.PatchOffset)
	if err != nil {
		return err
	}
	if p.PatchOffset+p.PatchLength == oldSize {
		return outfile.Truncate(p.PatchOffset + int64(len(p.Patch)))
	}
	return nil
}

func canOverwrite(ininfo, outinfo os.FileInfo) bool {
	if !outinfo.Mode().IsRegular() {
		return false
	}
	if !os.SameFile(ininfo, outinfo) {
		return false
	}
	if hasLinks(outinfo) {
		return false
	}
	return true
}
