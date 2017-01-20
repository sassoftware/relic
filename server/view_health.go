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

package server

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"sync"
	"time"

	"gerrit-pdt.unx.sas.com/tools/relic.git/config"
)

var (
	healthStatus   bool = true
	healthLastPing time.Time
	healthMu       sync.Mutex
)

const HealthCheckInterval = time.Second * 30
const PingTimeout = time.Second * 5

func (s *Server) startHealthCheck(force bool) error {
	if !s.healthCheck() && !force {
		return errors.New("health check failed")
	}
	go s.healthCheckLoop()
	return nil
}

func (s *Server) healthCheckLoop() {
	t := time.NewTimer(HealthCheckInterval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			s.healthCheck()
			t.Reset(HealthCheckInterval)
		case <-s.Closed:
			break
		}
	}
}

func (s *Server) healthCheck() bool {
	healthMu.Lock()
	last := healthStatus
	healthMu.Unlock()
	ok := true
	sawToken := make(map[string]bool)
	for _, keyConf := range s.Config.Keys {
		if keyConf.Token == "" || len(keyConf.Roles) == 0 || sawToken[keyConf.Token] {
			continue
		}
		sawToken[keyConf.Token] = true
		if !s.pingOne(keyConf) {
			ok = false
			break
		}
	}
	if ok != last {
		if ok {
			s.Logf("health status changed to OK")
		} else {
			s.Logf("health status changed to ERROR")
		}
	}
	healthMu.Lock()
	defer healthMu.Unlock()
	healthStatus = ok
	healthLastPing = time.Now()
	return ok
}

func (s *Server) pingOne(keyConf *config.KeyConfig) bool {
	ctx, cancel := context.WithTimeout(context.Background(), PingTimeout)
	defer cancel()
	var output bytes.Buffer
	proc := exec.CommandContext(ctx, os.Args[0], "ping", "--config", s.Config.Path(), "--key", keyConf.Name())
	proc.Stdout = &output
	proc.Stderr = &output
	err := proc.Run()
	if err == nil {
		return true
	}
	select {
	case <-ctx.Done():
		s.Logf("error: health check of key %s timed out", keyConf.Name())
	default:
		s.Logf("error: health check of key %s failed: %s\n%s\n", err, output.String())
	}
	return false
}

func (s *Server) serveHealth(request *http.Request) (res Response, err error) {
	if request.Method != "GET" {
		return ErrorResponse(http.StatusMethodNotAllowed), nil
	}
	healthMu.Lock()
	defer healthMu.Unlock()
	if time.Since(healthLastPing) > 3*HealthCheckInterval {
		s.Logr(request, "error: health check AWOL for %d seconds", time.Since(healthLastPing)/time.Second)
		return StringResponse(http.StatusInternalServerError, "ERROR"), nil
	} else if healthStatus {
		return StringResponse(http.StatusOK, "OK"), nil
	} else {
		return StringResponse(http.StatusInternalServerError, "ERROR"), nil
	}
}
