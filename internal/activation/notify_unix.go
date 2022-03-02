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
//
//go:build !windows
// +build !windows

package activation

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"syscall"
)

// DaemonReady signals to a parent init system or daemon manager that the
// daemon is finished starting up. Use after all listening sockets have been
// opened.
func DaemonReady() (err error) {
	if name := os.Getenv("NOTIFY_SOCKET"); name != "" {
		// systemd
		if err2 := writePath(name, "unixgram", "READY=1"); err2 != nil {
			err = err2
		}
	}
	if fdstr := os.Getenv("NOTIFY_FD"); fdstr != "" {
		// github.com/pusher/crank
		if err2 := writeFd(fdstr, "READY=1"); err2 != nil {
			err = err2
		}
	}
	if fdstr := os.Getenv("EINHORN_SOCK_FD"); fdstr != "" {
		// einhorn -g
		if err2 := writeFd(fdstr, einhornReadyStr()); err2 != nil {
			err = err2
		}
	} else if name := os.Getenv("EINHORN_SOCK_PATH"); name != "" {
		// github.com/stripe/einhorn
		if err2 := writePath(name, "unix", einhornReadyStr()); err2 != nil {
			err = err2
		}
	}
	return
}

// write a string to the unix socket at the named path
func writePath(path, netType, message string) error {
	sockAddr := &net.UnixAddr{Name: path, Net: netType}
	conn, err := net.DialUnix(netType, nil, sockAddr)
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write([]byte(message))
	return err
}

// write a string to a numeric file descriptor
func writeFd(fdstr, message string) error {
	fd, err := strconv.Atoi(fdstr)
	if err != nil {
		return err
	}
	_, err = syscall.Write(fd, []byte(message))
	return err
}

func einhornReadyStr() string {
	return fmt.Sprintf(`{"command":"worker:ack", "pid":%d}`+"\n", os.Getpid())
}
