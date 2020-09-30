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

package activatecmd

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

var prefixes = []string{"NOTIFY_", "LISTEN_", "EINHORN_"}

// ClearEnv removes all items from an environment list that might be interpreted
// as a notification socket or inherited fd
func ClearEnv(env []string) (ret []string) {
	for _, e := range env {
		ok := true
		for _, prefix := range prefixes {
			if strings.HasPrefix(e, prefix) {
				ok = false
				break
			}
		}
		if ok {
			ret = append(ret, e)
		}
	}
	return
}

type ListenerSet struct {
	files []*os.File
}

// NewListenerSet prepares a set of listeners that can be attached to child processes.
//
// The underyling files are duplicated, so the original Listener objects can be
// closed if desired.
func NewListenerSet(listeners []net.Listener) (*ListenerSet, error) {
	s := new(ListenerSet)
	for i, lis := range listeners {
		lf, ok := lis.(filer)
		if !ok {
			return nil, fmt.Errorf("unable to get file from listener %d (type %T)", i, lis)
		}
		f, err := lf.File()
		if err != nil {
			return nil, fmt.Errorf("unable to get file from listener %d: %w", i, err)
		}
		// File() puts the file description into blocking mode. Put it back and
		// leave it that way, otherwise it will race with child processes
		// trying to accept from it.
		if err := syscall.SetNonblock(int(f.Fd()), true); err != nil {
			return nil, fmt.Errorf("unable to get file from listener %d: %w", i, err)
		}
		s.files = append(s.files, f)
	}
	return s, nil
}

// Close frees the extra file descriptors owned by the listener set
func (s *ListenerSet) Close() error {
	for _, f := range s.files {
		f.Close()
	}
	return nil
}

// Attach all the listeners in the set to a new child process.
func (s *ListenerSet) Attach(cmd *exec.Cmd) error {
	if cmd.Env == nil {
		cmd.Env = ClearEnv(os.Environ())
	}
	for i, f := range s.files {
		cmd.Env = append(cmd.Env, fmt.Sprintf("EINHORN_FD_%d=%d", i, 3+len(cmd.ExtraFiles)))
		cmd.ExtraFiles = append(cmd.ExtraFiles, f)
	}
	cmd.Env = append(cmd.Env, fmt.Sprintf("EINHORN_FD_COUNT=%d", len(s.files)))
	cmd.Env = append(cmd.Env, fmt.Sprintf("EINHORN_MASTER_PID=%d", os.Getpid()))
	return nil
}

type filer interface {
	File() (*os.File, error)
}
