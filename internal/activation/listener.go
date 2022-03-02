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

// Package activation provides utilities for inheriting listening sockets from
// systemd, einhorn, socketmaster, and crank.
package activation

import (
	"errors"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// GetListener checks if a daemon manager has passed a pre-activated listener
// socket. If not, then net.Listener is used to open a new one. index starts at
// 0 and increments for each additional socket being inherited.
func GetListener(index uint, family, laddr string) (listener net.Listener, err error) {
	listener, err = einhornListener(index)
	if listener != nil || err != nil {
		return
	}
	listener, err = socketmasterListener(index)
	if listener != nil || err != nil {
		return
	}
	listener, err = systemdListener(index)
	if listener != nil || err != nil {
		return
	}
	if family == "unix" || family == "unixpacket" {
		os.Remove(laddr)
	}
	return net.Listen(family, laddr)
}

// Env vars are unset as they are read to avoid passing them to child
// processes, but keep their values locally in case more than one socket is
// being inherited
var savedEnv map[string]string

func popEnv(name string) string {
	if savedEnv == nil {
		savedEnv = make(map[string]string, 1)
	}
	val := savedEnv[name]
	if val != "" {
		return val
	}
	val = os.Getenv(name)
	savedEnv[name] = val
	os.Unsetenv(name)
	return val
}

func popEnvInt(name string) (int, error) {
	str := popEnv(name)
	if str == "" {
		return -1, nil
	}
	return strconv.Atoi(str)
}

func fdListener(fd uintptr) (net.Listener, error) {
	if err := syscall.SetNonblock(int(fd), true); err != nil {
		return nil, err
	}
	file := os.NewFile(fd, "FD_"+strconv.Itoa(int(fd)))
	// FileListener dupes the fd so make sure the originally inherited one gets closed
	defer file.Close()
	return net.FileListener(file)
}

func systemdListener(index uint) (net.Listener, error) {
	// systemd's socket activation places all fds sequentially starting at 3.
	// It also sets LISTEN_PID to this process' PID as a safety check. Other
	// runners may not set LISTEN_PID so don't worry if it's not set.
	pid, err := popEnvInt("LISTEN_PID")
	if err != nil || (pid != -1 && pid != os.Getpid()) {
		// This FD is not for us
		return nil, err
	}
	nfds, err := popEnvInt("LISTEN_FDS")
	if err != nil || nfds < int(index)+1 {
		return nil, err
	}
	return fdListener(uintptr(3 + index))
}

func einhornListener(index uint) (net.Listener, error) {
	// github.com/stripe/einhorn
	// Verify the parent PID as a safety check. Each fd is passed in its own
	// environment variable.
	ppid, err := popEnvInt("EINHORN_MASTER_PID")
	if err != nil || (ppid != -1 && ppid != os.Getppid()) {
		// This FD is not for us
		return nil, err
	}
	numfds, err := popEnvInt("EINHORN_FD_COUNT")
	if err != nil || numfds < int(index)+1 {
		return nil, err
	}
	name := "EINHORN_FD_" + strconv.Itoa(int(index))
	fd, err := popEnvInt(name)
	if err != nil {
		return nil, err
	} else if fd < 0 {
		return nil, errors.New("Missing environment variable " + name)
	}
	// Make sure the old-style var is not inherited by anybody
	os.Unsetenv("EINHORN_FDS")
	return fdListener(uintptr(fd))
}

func socketmasterListener(index uint) (net.Listener, error) {
	// github.com/zimbatm/socketmaster
	// Old style of einhorn fd passing, which socketmaster emulates. Uses a
	// single environment variable with a space-separated list of fds.
	fdstr := popEnv("EINHORN_FDS")
	if fdstr == "" {
		return nil, nil
	}
	fds := strings.Split(fdstr, " ")
	if len(fds) < int(index)+1 {
		return nil, nil
	}
	fd, err := strconv.Atoi(fds[index])
	if err != nil {
		return nil, err
	}
	return fdListener(uintptr(fd))
}
