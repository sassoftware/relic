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

package assuan

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"

	"github.com/sassoftware/relic/v7/lib/dlog"
)

// Simple libassuan client
//
// See: https://www.gnupg.org/software/libassuan/index.html

const (
	StatusOk      = "OK"
	StatusErr     = "ERR"
	StatusInquire = "INQUIRE"
	StatusData    = "D"
	StatusLines   = "S"
	StatusComment = "#"
)

type Conn struct {
	conn net.Conn
	r    *bufio.Reader
	mu   sync.Mutex
}

type Response struct {
	Status        string
	StatusMessage string
	Lines         []string
	Blob          []byte
}

func (r Response) Error() string {
	return fmt.Sprintf("response error: %s", r.StatusMessage)
}

type InquireFunc func(inquireLine string, msgLines []string) (string, error)

var InquireCancel = errors.New("inquiry cancelled")

func Dial(path string) (*Conn, error) {
	conn, err := net.Dial("unix", path)
	if err != nil {
		return nil, err
	}
	s := &Conn{
		conn: conn,
		r:    bufio.NewReader(conn),
	}
	status, msg, err := s.readLine()
	if err != nil {
		conn.Close()
		return nil, err
	} else if status != StatusOk {
		conn.Close()
		return nil, fmt.Errorf("failed to connect to %s: %s", path, msg)
	}
	return s, nil
}

func (c *Conn) write(cmd string) error {
	dlog.Printf(7, "> %#v", cmd)
	_, err := c.conn.Write([]byte(cmd))
	return err
}

func (c *Conn) data(data string) error {
	data = url.PathEscape(data)
	for len(data) > 0 {
		n := 512
		if n > len(data) {
			n = len(data)
		}
		chunk := data[:n]
		data = data[n:]
		if err := c.write(fmt.Sprintf("D %s\n", chunk)); err != nil {
			return err
		}
	}
	return c.write("END\n")
}

func (c *Conn) readLine() (string, string, error) {
	line, err := c.r.ReadString('\n')
	if err != nil {
		return "", "", err
	}
	line = line[:len(line)-1]
	dlog.Printf(7, "< %#v", line)
	parts := strings.SplitN(line, " ", 2)
	status := parts[0]
	if len(parts) > 1 {
		return status, parts[1], nil
	}
	return status, "", nil
}

func (c *Conn) read(inquire InquireFunc) (res Response, err error) {
	var quotedBlob string
	var saved error
readloop:
	for {
		status, msg, err := c.readLine()
		if err != nil {
			return res, err
		}
		switch status {
		case StatusData:
			quotedBlob += msg
		case StatusLines:
			msg, err := url.PathUnescape(msg)
			if err != nil {
				return res, err
			}
			res.Lines = append(res.Lines, msg)
		case StatusInquire:
			if inquire != nil {
				d, err := inquire(msg, res.Lines)
				if err != nil {
					_ = c.write("CANCEL\n")
					if err != InquireCancel {
						// raise this once the ERR has been received
						saved = err
					}
				} else {
					if err := c.data(d); err != nil {
						return res, err
					}
				}
			} else {
				_ = c.write("CANCEL\n")
			}
		case StatusComment:
			// no-op
		default:
			res.Status = status
			res.StatusMessage = msg
			break readloop
		}
	}
	if len(quotedBlob) > 0 {
		blob, err := url.PathUnescape(quotedBlob)
		if err != nil {
			return res, err
		}
		res.Blob = []byte(blob)
	}
	err = saved
	return
}

// Execute a command and retrieve the result.
//
// If an INQUIRE is received then inquire() will be invoked with the text after
// INQUIRE and all status lines received so far. It should return data to send,
// or it can return an err of InquireCancel which will cause a CANCEL to be
// sent and the resulting response to be returned. If inquire is nil then a
// CANCEL is always sent.
func (c *Conn) Transact(command string, inquire InquireFunc) (res Response, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil {
		return res, errors.New("connection is closed")
	}
	if err := c.write(command + "\n"); err != nil {
		return res, err
	}
	res, err = c.read(inquire)
	if err == nil && res.Status != StatusOk {
		err = res
	}
	return
}

func (c *Conn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
		c.r = nil
	}
	return nil
}
