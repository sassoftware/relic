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

package atomicfile

import (
	"errors"
	"io"
	"io/ioutil"
	"os"
	"path"
)

type AtomicFile interface {
	io.WriteCloser
	Commit() error
}

type atomicFile struct {
	name     string
	tempfile *os.File
}

func New(name string) (AtomicFile, error) {
	tempfile, err := ioutil.TempFile(path.Dir(name), path.Base(name)+".tmp")
	if err != nil {
		return nil, err
	}
	return &atomicFile{name, tempfile}, nil
}

func (f *atomicFile) Write(d []byte) (int, error) {
	return f.tempfile.Write(d)
}

func (f *atomicFile) Close() error {
	if f.tempfile == nil {
		return nil
	}
	f.tempfile.Close()
	os.Remove(f.tempfile.Name())
	f.tempfile = nil
	return nil
}

func (f *atomicFile) Commit() error {
	if f.tempfile == nil {
		return errors.New("file is closed")
	}
	f.tempfile.Chmod(0644)
	f.tempfile.Close()
	// rename can't overwrite on windows
	if err := os.Remove(f.name); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.Rename(f.tempfile.Name(), f.name); err != nil {
		return err
	}
	f.tempfile = nil
	return nil
}
