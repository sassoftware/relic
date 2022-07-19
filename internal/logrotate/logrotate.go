// Copyright © SAS Institute Inc.
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

package logrotate

import (
	"os"
	"sync"
)

type Writer struct {
	path string
	f    *os.File
	fi   os.FileInfo
	mu   sync.Mutex
}

func NewWriter(path string) (*Writer, error) {
	w := &Writer{path: path}
	return w, w.openLocked()
}

func (w *Writer) openLocked() error {
	// open for appending
	f, err := os.OpenFile(w.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0666)
	if err != nil {
		return err
	}
	// stat file to get inode to compare against later
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if w.f != nil {
		w.f.Close()
	}
	w.f = f
	w.fi = fi
	return nil
}

func (w *Writer) reopenLocked() error {
	if w.f != nil {
		fi, err := os.Stat(w.path)
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		if os.SameFile(fi, w.fi) {
			// file has not changed; do nothing
			return nil
		}
	}
	// file missing or changed, reopen
	return w.openLocked()
}

func (w *Writer) Write(d []byte) (n int, err error) {
	w.mu.Lock()
	err = w.reopenLocked()
	if err == nil {
		n, err = w.f.Write(d)
	}
	w.mu.Unlock()
	return
}

func (w *Writer) Close() (err error) {
	w.mu.Lock()
	if w.f != nil {
		err = w.f.Close()
		w.f = nil
	}
	w.mu.Unlock()
	return
}
