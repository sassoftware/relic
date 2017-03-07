// +build !windows

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

package audit

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"syscall"
)

const EnvAuditFd = "RELIC_AUDIT_FD"

// Write audit record to an inherited file descriptor. This is how the
// subprocess that does the actual signing conveys audit data back to the
// server for its own logs.
func (info *AuditInfo) WriteFd() error {
	fdstr := os.Getenv(EnvAuditFd)
	if fdstr == "" {
		return nil
	}
	blob, err := info.Marshal()
	if err != nil {
		return err
	}
	fd, err := strconv.Atoi(fdstr)
	if err != nil {
		return err
	}
	newfd, err := syscall.Dup(fd)
	if err != nil {
		return err
	}
	af := os.NewFile(uintptr(newfd), "<audit>")
	defer af.Close()
	_, err = af.Write(blob)
	return err
}

// A pipe used to receive audit data from a signing subprocess
type PipeReader struct {
	r, w   *os.File
	errch  chan error
	blobch chan []byte
}

// Make a pipe to receive audit data from the signing tool
func AttachCmd(proc *exec.Cmd, extraAttrs map[string]string) (*PipeReader, error) {
	r, w, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	fdno := 3 + len(proc.ExtraFiles)
	proc.ExtraFiles = append(proc.ExtraFiles, w)
	if proc.Env == nil {
		proc.Env = os.Environ()
	}
	for k, v := range extraAttrs {
		proc.Env = append(proc.Env, fmt.Sprintf("RELIC_ATTR_%s=%s", k, v))
	}
	proc.Env = append(proc.Env, fmt.Sprintf("%s=%d", EnvAuditFd, fdno))
	errch := make(chan error, 1)
	blobch := make(chan []byte, 1)
	go func() {
		var buf bytes.Buffer
		_, err := io.Copy(&buf, r)
		blobch <- buf.Bytes()
		errch <- err
	}()
	return &PipeReader{r, w, errch, blobch}, nil
}

// Called after the process starts to close the write end of the pipe, which
// belongs to the child process now.
func (pr *PipeReader) Start() {
	pr.w.Close()
	pr.w = nil
}

// Get audit result after the process has exited
func (pr *PipeReader) Get() (*AuditInfo, error) {
	blob := <-pr.blobch
	err := <-pr.errch
	if err != nil {
		return nil, err
	} else if len(blob) == 0 {
		return nil, nil
	}
	return Parse(blob)
}

func (pr *PipeReader) Close() error {
	if pr.w != nil {
		pr.w.Close()
		pr.w = nil
	}
	if pr.r != nil {
		pr.r.Close()
		pr.r = nil
	}
	return nil
}
