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
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/sassoftware/relic/v7/internal/workerrpc"
	"github.com/sassoftware/relic/v7/token"
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
			log.Printf("token error (attempt %d of %d): %s", i, retries, last)
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
		if req.GetBody != nil {
			req.Body, err = req.GetBody()
			if err != nil {
				return nil, err
			}
		}
		ctx, cancel := context.WithTimeout(baseCtx, timeout)
		defer cancel()
		resp, err := http.DefaultClient.Do(req.WithContext(ctx))
		if err != nil {
			if baseCtx.Err() != nil {
				// cancelled
				return nil, baseCtx.Err()
			}
			// network errror
			if !errIsTemporary(err) {
				return nil, err
			}
			last = err
		} else if resp.StatusCode == http.StatusOK {
			// json response
			blob, err := ioutil.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				return nil, err
			}
			rresp = new(workerrpc.Response)
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
			last = errors.New(rresp.Err)
			if !rresp.Retryable {
				break
			}
		} else {
			// http error
			body, _ := ioutil.ReadAll(resp.Body)
			resp.Body.Close()
			last = fmt.Errorf("HTTP request failed: %s\nRequest: %s %s\n\n%s", resp.Status, req.Method, req.URL, string(body))
			if !statusIsTemporary(resp.StatusCode) {
				break
			}
		}
	}
	return nil, last
}

type temporary interface {
	Temporary() bool
}

func errIsTemporary(err error) bool {
	if err == context.DeadlineExceeded {
		return true
	}
	if e, ok := err.(temporary); ok && e.Temporary() {
		return true
	}
	// unpack error wrappers
	if e, ok := err.(*url.Error); ok {
		err = e.Err
	}
	if e, ok := err.(*net.OpError); ok {
		err = e.Err
	}
	// treat any syscall error as something recoverable
	if _, ok := err.(*os.SyscallError); ok {
		return true
	}
	return false
}

func statusIsTemporary(statusCode int) bool {
	switch statusCode {
	case http.StatusGatewayTimeout,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusInsufficientStorage,
		http.StatusInternalServerError:
		return true
	default:
		return false
	}
}
