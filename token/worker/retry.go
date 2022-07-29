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
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/sassoftware/relic/v7/internal/httperror"
	"github.com/sassoftware/relic/v7/internal/workerrpc"
	"github.com/sassoftware/relic/v7/token"
	"github.com/sassoftware/relic/v7/token/tokencache"
)

const (
	initialDelay = 1 * time.Second
	scaleFactor  = 2.718
	maxDelay     = 30 * time.Second
)

func (t *WorkerToken) doRetry(req *http.Request) (rresp *workerrpc.Response, err error) {
	retries := t.tconf.Retries
	if retries == 0 {
		retries = defaultRetries
	}
	timeout := time.Duration(t.tconf.Timeout) * time.Second
	if timeout == 0 {
		timeout = defaultTimeout
	}
	baseCtx := req.Context()
	delay := float32(initialDelay)
	var last error
	for i := 0; i < retries; i++ {
		if i != 0 {
			log.Warn().
				Int("attempt", i).
				Int("max_attempts", retries).
				AnErr("last_error", last).
				Msg("token error; retrying")
			// delay retry with backoff
			ctx, cancel := context.WithTimeout(baseCtx, time.Duration(delay))
			<-ctx.Done()
			cancel()
			if baseCtx.Err() != nil {
				// cancelled
				return nil, baseCtx.Err()
			}
			delay *= scaleFactor
			if delay > float32(maxDelay) {
				delay = float32(maxDelay)
			}
		}
		start := time.Now()
		rresp, err := t.doOnce(req, timeout)
		if err == nil {
			t.observe(req, start, http.StatusOK)
			return rresp, nil
		}
		// translate various outcomes into a status code for metrics
		var retry bool
		code := http.StatusInternalServerError
		if httperror.Temporary(err) {
			code = http.StatusServiceUnavailable
			retry = true
		} else if errors.As(err, new(token.KeyUsageError)) {
			code = http.StatusBadRequest
		}
		if e := new(httperror.ResponseError); errors.As(err, e) {
			code = e.StatusCode
		}
		if baseCtx.Err() != nil {
			// request canceled
			code = 499
		} else if errors.Is(err, context.DeadlineExceeded) {
			code = http.StatusGatewayTimeout
		}
		t.observe(req, start, code)
		if !retry {
			return nil, err
		}
		last = err
	}
	return nil, last
}

func (t *WorkerToken) doOnce(req *http.Request, timeout time.Duration) (*workerrpc.Response, error) {
	ctx, cancel := context.WithTimeout(req.Context(), timeout)
	defer cancel()
	if req.GetBody != nil {
		var err error
		req.Body, err = req.GetBody()
		if err != nil {
			return nil, err
		}
	}
	resp, err := http.DefaultClient.Do(req.WithContext(ctx))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// http error
		return nil, httperror.FromResponse(resp)
	}
	// json response
	blob, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	rresp := new(workerrpc.Response)
	if err := json.Unmarshal(blob, rresp); err != nil {
		return nil, err
	}
	if rresp.Err == "" {
		// success
		return rresp, nil
	} else if rresp.Usage {
		return nil, token.KeyUsageError{
			Key: rresp.Key,
			Err: errors.New(rresp.Err),
		}
	}
	return nil, tokenError{Err: rresp.Err, Retryable: rresp.Retryable}
}

func (t *WorkerToken) observe(req *http.Request, start time.Time, code int) {
	dur := time.Since(start).Seconds()
	name := t.tconf.Name()
	op := strings.TrimLeft(req.URL.Path, "/")
	scode := strconv.FormatInt(int64(code), 10)
	tokencache.MetricOperations.WithLabelValues(name, op).Observe(dur)
	tokencache.MetricResponses.WithLabelValues(name, op, scode).Inc()
}

type tokenError struct {
	Err       string
	Retryable bool
}

func (e tokenError) Error() string   { return e.Err }
func (e tokenError) Temporary() bool { return e.Retryable }
