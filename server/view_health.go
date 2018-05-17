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

package server

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/sassoftware/relic/token/worker"
)

var (
	healthStatus   int
	healthLastPing time.Time
	healthMu       sync.Mutex
)

func (s *Server) startHealthCheck(force bool) error {
	if s.Config.Server.TokenCheckInterval > 0 {
		healthStatus = s.Config.Server.TokenCheckFailures
		if !s.healthCheck() && !force {
			return errors.New("health check failed")
		}
		go s.healthCheckLoop()
	}
	return nil
}

func (s *Server) healthCheckLoop() {
	t := time.NewTimer(time.Second * time.Duration(s.Config.Server.TokenCheckInterval))
	defer t.Stop()
	for {
		select {
		case <-t.C:
			s.healthCheck()
			t.Reset(time.Second * time.Duration(s.Config.Server.TokenCheckInterval))
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
	for _, token := range s.tokens {
		if !s.pingOne(token) {
			ok = false
		}
	}
	next := last
	if ok {
		if last == 0 {
			s.Logf("recovered to normal state, status is now OK")
		} else if last < s.Config.Server.TokenCheckFailures {
			s.Logf("recovered to normal state")
		}
		next = s.Config.Server.TokenCheckFailures
	} else if last > 0 {
		next--
		if next == 0 {
			s.Logf("exceeded maximum health check failures, flagging as ERROR")
		}
	}
	healthMu.Lock()
	defer healthMu.Unlock()
	healthStatus = next
	healthLastPing = time.Now()
	return ok
}

func (s *Server) pingOne(tok *worker.WorkerToken) bool {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*time.Duration(s.Config.Server.TokenCheckTimeout))
	defer cancel()
	if err := tok.PingContext(ctx); err != nil {
		if ctx.Err() != nil {
			s.Logf("error: health check of token %s timed out", tok.Config().Name())
		} else {
			s.Logf("error: health check of token %s failed: %s", tok.Config().Name(), err)
		}
		return false
	}
	return true
}

func (s *Server) Healthy(request *http.Request) bool {
	if s.Config.Server.Disabled {
		return false
	}
	if s.Config.Server.TokenCheckInterval <= 0 {
		return true
	}
	healthMu.Lock()
	defer healthMu.Unlock()
	if time.Since(healthLastPing) > 3*time.Second*time.Duration(s.Config.Server.TokenCheckInterval) {
		if request != nil {
			s.Logr(request, "error: health check AWOL for %d seconds", time.Since(healthLastPing)/time.Second)
		}
		return false
	}
	return healthStatus > 0
}

func (s *Server) serveHealth(request *http.Request) (res Response, err error) {
	if request.Method != "GET" {
		return ErrorResponse(http.StatusMethodNotAllowed), nil
	}
	if s.Healthy(request) {
		return StringResponse(http.StatusOK, "OK"), nil
	}
	return ErrorResponse(http.StatusServiceUnavailable), nil
}
