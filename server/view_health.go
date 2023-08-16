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
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/rs/zerolog/log"

	"github.com/sassoftware/relic/v7/internal/zhttp"
	"github.com/sassoftware/relic/v7/token"
)

var (
	healthStatus   int
	healthLastPing time.Time
	healthMu       sync.Mutex

	metricTokenCheckErrors = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "token_check_sequential_errors",
			Help: "Number of sequential errors seen while checking the token's status",
		},
		[]string{"token"},
	)
)

func (s *Server) healthCheckInterval() time.Duration {
	return time.Second * time.Duration(s.Config.Server.TokenCheckInterval)
}

func (s *Server) startHealthCheck() error {
	healthStatus = s.Config.Server.TokenCheckFailures
	healthLastPing = time.Now()
	go s.healthCheckLoop()
	return nil
}

func (s *Server) healthCheckLoop() {
	interval := s.healthCheckInterval()
	t := time.NewTimer(0)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			s.healthCheck()
			t.Reset(interval)
		case <-s.Closed:
			break
		}
	}
}

func (s *Server) healthCheck() bool {
	healthMu.Lock()
	last := healthStatus
	healthMu.Unlock()
	var notOK []string
	for name, token := range s.tokens {
		metric := metricTokenCheckErrors.WithLabelValues(name)
		if s.pingOne(token) {
			metric.Set(0)
		} else {
			metric.Inc()
			notOK = append(notOK, name)
		}
	}
	next := last
	if len(notOK) == 0 {
		ev := log.Info().Str("token_state", "OK")
		if last == 0 {
			ev.Msg("recovered to normal state, status is now OK")
		} else if last < s.Config.Server.TokenCheckFailures {
			ev.Msg("recovered to normal state")
		}
		next = s.Config.Server.TokenCheckFailures
	} else if last > 0 {
		next--
		if next == 0 {
			log.Error().Str("token_state", "ERROR").
				Msg("exceeded maximum health check failures, flagging as ERROR")
		}
	}
	healthMu.Lock()
	defer healthMu.Unlock()
	healthStatus = next
	healthLastPing = time.Now()
	return len(notOK) == 0
}

func (s *Server) pingOne(tok token.Token) bool {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*time.Duration(s.Config.Server.TokenCheckTimeout))
	defer cancel()
	if err := tok.Ping(ctx); err != nil {
		ev := log.Error().Str("token", tok.Config().Name())
		if ctx.Err() != nil {
			ev.Msg("token health check timed out")
		} else {
			ev.Err(err).Msg("token health check failed")
		}
		return false
	}
	return true
}

func (s *Server) Healthy(request *http.Request) bool {
	if s.Config.Server.Disabled {
		return false
	}
	healthMu.Lock()
	defer healthMu.Unlock()
	if time.Since(healthLastPing) > 3*s.healthCheckInterval() {
		if request != nil {
			log.Error().Dur("stale_for", time.Since(healthLastPing)).Msg("health check is stale")
		}
		return false
	}
	return healthStatus > 0
}

func (s *Server) serveHealth(rw http.ResponseWriter, request *http.Request) {
	zhttp.DontLog(request)
	if s.Healthy(request) {
		_, _ = rw.Write([]byte("OK\r\n"))
	} else {
		http.Error(rw, "health check failed", http.StatusServiceUnavailable)
	}
}
