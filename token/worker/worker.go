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

package worker

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"github.com/sassoftware/relic/v7/config"
	"github.com/sassoftware/relic/v7/internal/activation/activatecmd"
	"github.com/sassoftware/relic/v7/internal/closeonce"
)

const (
	startTimeout = 60 * time.Second
	restartDelay = 10 * time.Second
)

func getCookie() string {
	cookieBytes := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, cookieBytes); err != nil {
		panic(err)
	}
	return fmt.Sprintf("%x", cookieBytes)
}

type WorkerToken struct {
	config *config.Config
	tconf  *config.TokenConfig
	cookie string
	addr   string
	fdset  *activatecmd.ListenerSet
	notify *activatecmd.Listener
	closed closeonce.Closed
	wg     sync.WaitGroup
	ctx    context.Context
	cancel context.CancelFunc

	mu          sync.Mutex
	procs       map[int]struct{}
	procsExited chan int
}

func New(config *config.Config, tokenName string) (*WorkerToken, error) {
	tconf, err := config.GetToken(tokenName)
	if err != nil {
		return nil, err
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	fdset, err := activatecmd.NewListenerSet([]net.Listener{lis})
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	t := &WorkerToken{
		config:      config,
		tconf:       tconf,
		cookie:      getCookie(),
		fdset:       fdset,
		notify:      new(activatecmd.Listener),
		addr:        lis.Addr().String(),
		ctx:         ctx,
		cancel:      cancel,
		procs:       make(map[int]struct{}),
		procsExited: make(chan int, 10),
	}
	lis.Close() // NewListenerSet dupes this so it's not needed anymore
	if err := t.spawn(); err != nil {
		return nil, err
	}
	t.wg.Add(1)
	go t.monitor()
	return t, nil
}

func (t *WorkerToken) spawn() error {
	// build cmdline and worker options
	self, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(os.Args[0], "worker", t.config.Path(), t.tconf.Name())
	cmd.Path = self
	cmd.Stdin = bytes.NewReader([]byte(t.cookie))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	// attach shared listener socket
	cmd.Env = activatecmd.ClearEnv(os.Environ())
	if err := t.fdset.Attach(cmd); err != nil {
		return err
	}
	// attach notify socket so we know when the process is ready or if it died on init
	detach, err := t.notify.Attach(cmd)
	if err != nil {
		return err
	}
	defer detach()
	// start process and wait for ready state
	if err := cmd.Start(); err != nil {
		return err
	}
	detach()
	pid := cmd.Process.Pid
	exited := make(chan struct{})
	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		_ = cmd.Wait()
		t.procsExited <- pid
		close(exited)
	}()
	t.mu.Lock()
	t.procs[pid] = struct{}{}
	t.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), startTimeout)
	defer cancel()
	select {
	case <-t.notify.Ready():
		// ready
	case <-ctx.Done():
		// timed out
		_ = cmd.Process.Kill()
		return fmt.Errorf("token \"%s\" worker timed out during startup", t.tconf.Name())
	case <-exited:
		// terminated
		return fmt.Errorf("token \"%s\" worker exited prematurely", t.tconf.Name())
	}
	return nil
}

func (t *WorkerToken) countWorkers() int {
	t.mu.Lock()
	n := len(t.procs)
	t.mu.Unlock()
	return n
}

func (t *WorkerToken) monitor() {
	defer t.wg.Done()
	target := 1
	if t.config.Server != nil && t.config.Server.NumWorkers > 0 {
		target = t.config.Server.NumWorkers
	}
	for t.ctx.Err() == nil {
		for t.countWorkers() < target {
			if err := t.spawn(); err != nil {
				log.Printf("error: failed to spawn worker process: %s", err)
				select {
				case <-time.After(restartDelay):
				case <-t.ctx.Done():
					return
				}
			}
		}
		select {
		case <-t.ctx.Done():
			return
		case pid := <-t.procsExited:
			// process exited
			t.removePid(pid)
		case pid := <-t.notify.Stopping():
			// process hit an error and will exit soon
			t.removePid(pid)
		}
	}
}

func (t *WorkerToken) removePid(pid int) {
	t.mu.Lock()
	delete(t.procs, pid)
	t.mu.Unlock()
}

func (t *WorkerToken) Close() error {
	if t == nil {
		return nil
	}
	return t.closed.Close(func() error {
		t.cancel()
		t.mu.Lock()
		for pid := range t.procs {
			_ = syscall.Kill(pid, syscall.SIGTERM)
		}
		t.mu.Unlock()
		t.wg.Wait()
		t.fdset.Close()
		t.notify.Close()
		return nil
	})
}
