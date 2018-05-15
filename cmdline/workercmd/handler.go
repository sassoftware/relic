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

package workercmd

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/miekg/pkcs11"
	"github.com/sassoftware/relic/cmdline/shared"
	"github.com/sassoftware/relic/internal/workerrpc"
	"github.com/sassoftware/relic/token"
)

const (
	defaultInterval = 60 * time.Second
	defaultTimeout  = 30 * time.Second
)

// an arbitarily-chosen set of error codes that indicate that the token session
// is busted and that the worker should exit and start over
var fatalErrors = map[pkcs11.Error]bool{
	pkcs11.CKR_CRYPTOKI_NOT_INITIALIZED: true,
	pkcs11.CKR_DEVICE_REMOVED:           true,
	pkcs11.CKR_GENERAL_ERROR:            true,
	pkcs11.CKR_HOST_MEMORY:              true,
	pkcs11.CKR_LIBRARY_LOAD_FAILED:      true,
	pkcs11.CKR_SESSION_CLOSED:           true,
	pkcs11.CKR_SESSION_HANDLE_INVALID:   true,
	pkcs11.CKR_TOKEN_NOT_PRESENT:        true,
	pkcs11.CKR_TOKEN_NOT_RECOGNIZED:     true,
	pkcs11.CKR_USER_NOT_LOGGED_IN:       true,
}

func (h *handler) healthCheck() {
	interval := defaultInterval
	timeout := defaultTimeout
	if shared.CurrentConfig.Server != nil {
		if shared.CurrentConfig.Server.TokenCheckInterval != 0 {
			interval = time.Duration(shared.CurrentConfig.Server.TokenCheckInterval) * time.Second
		}
		if shared.CurrentConfig.Server.TokenCheckTimeout != 0 {
			timeout = time.Duration(shared.CurrentConfig.Server.TokenCheckTimeout) * time.Second
		}
	}
	ppid := os.Getppid()
	tick := time.NewTicker(interval)
	tmt := time.NewTimer(timeout)
	errch := make(chan error)
	for {
		// check if parent process went away
		if os.Getppid() != ppid {
			log.Println("error: parent process disappeared, worker stopping")
			h.shutdown()
			return
		}
		// check if token is alive
		go func() {
			errch <- h.token.Ping()
		}()
		var err error
		select {
		case err = <-errch:
			// ping completed
		case <-tmt.C:
			// timed out
			err = fmt.Errorf("timed out after %s", timeout)
		}
		if err != nil {
			// stop the worker on error
			log.Printf("error: health check of token \"%s\" failed: %s", h.token.Config().Name(), err)
			h.shutdown()
			return
		}
		// wait for next tick
		<-tick.C
		// reset timeout
		if !tmt.Stop() {
			<-tmt.C
		}
		tmt.Reset(timeout)
	}
}

type handler struct {
	token    token.Token
	cookie   []byte
	keyCache sync.Map
	shutdown func()
}

func (h *handler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// validate auth cookie
	cookie := req.Header.Get("Auth-Cookie")
	if !hmac.Equal([]byte(cookie), []byte(h.cookie)) {
		rw.WriteHeader(http.StatusForbidden)
		return
	}
	// dispatch
	resp, err := h.handle(rw, req)
	if err != nil {
		resp.Retryable = true
		resp.Err = err.Error()
		if e, ok := err.(pkcs11.Error); ok {
			if fatalErrors[e] {
				log.Printf("error: terminating worker for token \"%s\" due to error: %s", h.token.Config().Name(), err)
				go h.shutdown()
				// errors that cause the worker to restart are also retryable
				resp.Retryable = true
			} else {
				// pkcs11 errors not in fatalErrors are probably user error, so don't retry
				resp.Retryable = false
			}
		}
	}
	// marshal response
	blob, err := json.Marshal(resp)
	if err != nil {
		log.Printf("error: worker for token \"%s\": %s", h.token.Config().Name(), err)
		return
	}
	rw.Write(blob)
}

func (h *handler) handle(rw http.ResponseWriter, req *http.Request) (resp workerrpc.Response, err error) {
	blob, err := ioutil.ReadAll(req.Body)
	if err != nil {
		return resp, err
	}
	var rr workerrpc.Request
	if err := json.Unmarshal(blob, &rr); err != nil {
		return resp, err
	}
	switch req.URL.Path {
	case workerrpc.Ping:
		return resp, h.token.Ping()
	case workerrpc.GetKey:
		key, err := h.getKey(rr.KeyName)
		if err != nil {
			return resp, err
		}
		resp.ID = key.GetID()
		resp.Value, err = x509.MarshalPKIXPublicKey(key.Public())
		return resp, err
	case workerrpc.Sign:
		hash := crypto.Hash(rr.Hash)
		opts := crypto.SignerOpts(hash)
		if rr.SaltLength != nil {
			opts = &rsa.PSSOptions{SaltLength: *rr.SaltLength, Hash: hash}
		}
		key, err := h.getKey(rr.KeyName)
		if err != nil {
			return resp, err
		}
		resp.Value, err = key.Sign(rand.Reader, rr.Digest, opts)
		return resp, err
	default:
		return resp, errors.New("invalid method: " + req.URL.Path)
	}
}

// cache key handles
func (h *handler) getKey(keyName string) (token.Key, error) {
	key, _ := h.keyCache.Load(keyName)
	if key == nil {
		var err error
		key, err = h.token.GetKey(keyName)
		if err != nil {
			return nil, err
		}
		h.keyCache.Store(keyName, key)
	}
	return key.(token.Key), nil
}
