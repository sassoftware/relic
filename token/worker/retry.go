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
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"
)

const (
	reqRetryDelay = 10 * time.Second
	reqNumRetries = 5
)

func doRetry(req *http.Request) (resp *http.Response, err error) {
	var last error
	for i := 0; i < reqNumRetries; i++ {
		if i != 0 {
			time.Sleep(reqRetryDelay)
		}
		if req.GetBody != nil {
			req.Body, err = req.GetBody()
			if err != nil {
				return nil, err
			}
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			// network errror
			if !errIsTemporary(err) {
				return nil, err
			}
			last = err
		} else if resp.StatusCode < 400 {
			// success
			return resp, nil
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
