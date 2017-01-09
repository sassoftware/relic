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
	"io/ioutil"
	"os"
	"path"
)

type PatchInfo struct {
	PatchOffset uint64 `json:"patch_offset,omitempty"`
	PatchLength uint64 `json:"patch_length,omitempty"`

	patch []byte
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
	info.patch = blob[idx+1:]
	return info, nil
}

func (p *PatchInfo) Apply(infile *os.File, outpath string) error {
	ininfo, err := infile.Stat()
	if err != nil {
		return err
	}
	if outpath == "-" {
		// send to stdout
		return p.apply(infile, os.Stdout)
	}
	outinfo, err := os.Lstat(outpath)
	if err == nil && p.PatchLength == uint64(len(p.patch)) && canOverwrite(ininfo, outinfo) {
		// overwrite
		return p.applyInPlace(infile)
	}
	// write-rename
	tempfile, err := ioutil.TempFile(path.Dir(outpath), path.Base(outpath))
	if err != nil {
		return err
	}
	defer func() {
		tempfile.Close()
		os.Remove(tempfile.Name())
	}()
	if err := p.apply(infile, tempfile); err != nil {
		return err
	}
	tempfile.Chmod(0644)
	tempfile.Close()
	// rename can't overwrite on windows
	if err := os.Remove(outpath); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.Rename(tempfile.Name(), outpath); err != nil {
		return err
	}
	return nil
}

func (p *PatchInfo) apply(infile io.ReadSeeker, outstream io.Writer) error {
	if _, err := infile.Seek(0, 0); err != nil {
		return err
	}
	if p.PatchOffset > 0 {
		if _, err := io.CopyN(outstream, infile, int64(p.PatchOffset)); err != nil {
			return err
		}
	}
	if n, err := outstream.Write(p.patch); err != nil {
		return err
	} else if n != len(p.patch) {
		return io.ErrShortWrite
	}
	if _, err := infile.Seek(int64(p.PatchOffset+p.PatchLength), 0); err != nil {
		return err
	}
	_, err := io.Copy(outstream, infile)
	return err
}

func (p *PatchInfo) applyInPlace(outfile *os.File) error {
	_, err := outfile.WriteAt(p.patch, int64(p.PatchOffset))
	return err
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
