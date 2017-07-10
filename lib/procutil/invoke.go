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

package procutil

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

type Command struct {
	Proc   *exec.Cmd
	Output string
	Pipes  map[int][]byte

	ctx    context.Context
	cancel context.CancelFunc
	pipes  []*piper
	stdio  *bytes.Buffer
}

// Prepare to launch a subprocess with the given command-line. The process will
// be terminated when ctx is cancelled or timeout elapses.
func CommandContext(ctx context.Context, cmdline []string, timeout time.Duration) *Command {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	proc := exec.CommandContext(ctx, cmdline[0], cmdline[1:]...)
	stdio := new(bytes.Buffer)
	proc.Stdout = stdio
	proc.Stderr = stdio
	return &Command{
		ctx:    ctx,
		Proc:   proc,
		stdio:  stdio,
		cancel: cancel,
	}
}

// Run the subprocess and wait for it to complete.
func (c *Command) Run() error {
	defer c.cancel()
	if err := c.Proc.Start(); err != nil {
		return err
	}
	for _, p := range c.pipes {
		if err := p.detach(); err != nil {
			return err
		}
		defer p.Close()
	}
	err := c.Proc.Wait()
	c.Output = c.stdio.String()
	if err != nil {
		select {
		case <-c.ctx.Done():
			return c.ctx.Err()
		default:
			return err
		}
	}
	c.Pipes = make(map[int][]byte)
	for _, p := range c.pipes {
		blob, err := p.get()
		if err != nil {
			return err
		}
		c.Pipes[p.fd] = blob
	}
	return nil
}

func (c *Command) FormatCmdline() string {
	words := make([]string, len(c.Proc.Args))
	for i, word := range c.Proc.Args {
		if strings.Index(word, " ") >= 0 {
			word = "\"" + word + "\""
		}
		words[i] = word
	}
	return strings.Join(words, " ")
}

type piper struct {
	r, w   *os.File
	fd     int
	errch  <-chan error
	blobch <-chan []byte
	err    error
	blob   []byte
}

// Attach a Reader to a pipe on the subprocess. Bytes will be copied from the
// reader to the pipe until EOF.
func (c *Command) AttachInput(r io.Reader) (int, error) {
	pr, pw, err := os.Pipe()
	if err != nil {
		return -1, err
	}
	fd := 3 + len(c.Proc.ExtraFiles)
	c.Proc.ExtraFiles = append(c.Proc.ExtraFiles, pr)
	errch := make(chan error, 1)
	go func() {
		_, err := io.Copy(pw, r)
		if err == io.ErrUnexpectedEOF {
			c.cancel()
		}
		pw.Close()
		errch <- err
	}()
	c.pipes = append(c.pipes, &piper{r: pr, w: pw, fd: fd, errch: errch})
	return fd, nil
}

// Attach a pipe to the subprocess. Bytes will be copied from the pipe until
// EOF and the result will be stored in Command.Pipes[fd] after Run() returns
func (c *Command) AttachOutput() (int, error) {
	pr, pw, err := os.Pipe()
	if err != nil {
		return -1, err
	}
	fd := 3 + len(c.Proc.ExtraFiles)
	c.Proc.ExtraFiles = append(c.Proc.ExtraFiles, pw)
	errch := make(chan error, 1)
	blobch := make(chan []byte, 1)
	go func() {
		var buf bytes.Buffer
		_, err := io.Copy(&buf, pr)
		pr.Close()
		blobch <- buf.Bytes()
		errch <- err
	}()
	c.pipes = append(c.pipes, &piper{r: pr, w: pw, fd: fd, errch: errch, blobch: blobch})
	return fd, nil
}

// close the remote end of the pipe, after the subprocess was spawned
func (p *piper) detach() (err error) {
	if p.blobch == nil {
		// writer
		return p.r.Close()
	}
	// reader
	return p.w.Close()
}

// close both ends of the pipe and surface any errors that occurred in a background goroutine
func (p *piper) Close() error {
	p.r.Close()
	return p.closeWriter()
}

// close the writer end of the pipe and surface any errors that occurred in a background goroutine
func (p *piper) closeWriter() error {
	p.w.Close()
	if p.errch != nil {
		p.err = <-p.errch
		p.errch = nil
	}
	return p.err
}

func (p *piper) get() ([]byte, error) {
	err := p.closeWriter()
	if err == nil && p.blobch != nil {
		p.blob = <-p.blobch
		p.blobch = nil
	}
	return p.blob, err
}
