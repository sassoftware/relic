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
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/sassoftware/relic/config"
	"github.com/sassoftware/relic/lib/compresshttp"
	"github.com/sassoftware/relic/lib/isologger"
	"github.com/sassoftware/relic/lib/x509tools"
	"github.com/sassoftware/relic/token/worker"
)

type Server struct {
	Config   *config.Config
	ErrorLog *log.Logger
	closeLog io.Closer
	logMu    sync.Mutex
	Closed   <-chan bool
	closeCh  chan<- bool
	tokens   map[string]*worker.WorkerToken
}

func (s *Server) callHandler(request *http.Request, lw *loggingWriter) (response Response, err error) {
	defer func() {
		if caught := recover(); caught != nil {
			const size = 64 << 10
			buf := make([]byte, size)
			buf = buf[:runtime.Stack(buf, false)]
			response = s.LogError(request, caught, buf)
			err = nil
		}
	}()
	ctx := request.Context()
	ctx, errResponse := s.getUserRoles(ctx, request)
	if errResponse != nil {
		return errResponse, nil
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	closed := lw.CloseNotify()
	go func() {
		select {
		case <-closed:
			cancel()
		case <-ctx.Done():
		}
	}()
	request = request.WithContext(ctx)
	lw.r = request
	if err := compresshttp.DecompressRequest(request); err == compresshttp.ErrUnacceptableEncoding {
		return StringResponse(http.StatusNotAcceptable, err.Error()), nil
	} else if err != nil {
		return nil, err
	}
	if request.URL.Path == "/health" {
		// this view is the only one allowed without a client cert
		return s.serveHealth(request)
	} else if GetClientName(request) == "" {
		return AccessDeniedResponse, nil
	} else if !s.Healthy(request) {
		return ErrorResponse(http.StatusServiceUnavailable), nil
	}
	if strings.HasPrefix(request.URL.Path, "/keys/") {
		return s.serveGetKey(request)
	}
	switch request.URL.Path {
	case "/":
		return s.serveHome(request)
	case "/list_keys":
		return s.serveListKeys(request)
	case "/sign":
		return s.serveSign(request, lw)
	case "/directory":
		return s.serveDirectory()
	default:
		return ErrorResponse(http.StatusNotFound), nil
	}
}

func formatSubject(cert *x509.Certificate) string {
	return x509tools.FormatPkixName(cert.RawSubject, x509tools.NameStyleOpenSsl)
}

func (s *Server) getUserRoles(ctx context.Context, request *http.Request) (context.Context, Response) {
	if request.TLS != nil && len(request.TLS.PeerCertificates) != 0 {
		cert := request.TLS.PeerCertificates[0]
		digest := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
		encoded := hex.EncodeToString(digest[:])
		var useDN bool
		client := s.Config.Clients[encoded]
		if client == nil {
			var saved error
			for _, c2 := range s.Config.Clients {
				match, err := c2.Match(request.TLS.PeerCertificates)
				if match {
					client = c2
					useDN = true
					break
				} else if err != nil {
					// preserve any potentially interesting validation errors
					saved = err
				}
			}
			if client == nil && saved != nil {
				s.Logr(request, "client cert verification failed: %s\n", saved)
			}
		}
		if client == nil {
			s.Logr(request, "access denied: unknown fingerprint %s on certificate: %s\n", encoded, formatSubject(cert))
			return nil, AccessDeniedResponse
		}
		name := client.Nickname
		if name == "" {
			name = encoded[:12]
		}
		ctx = context.WithValue(ctx, ctxClientName, name)
		ctx = context.WithValue(ctx, ctxRoles, client.Roles)
		if useDN {
			ctx = context.WithValue(ctx, ctxClientDN, formatSubject(cert))
		}
	}
	return ctx, nil
}

func (s *Server) CheckKeyAccess(request *http.Request, keyName string) *config.KeyConfig {
	keyConf, err := s.Config.GetKey(keyName)
	if err != nil {
		return nil
	}
	clientRoles := GetClientRoles(request)
	for _, keyRole := range keyConf.Roles {
		for _, clientRole := range clientRoles {
			if keyRole == clientRole {
				return keyConf
			}
		}
	}
	return nil
}

func (s *Server) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Accept-Encoding", compresshttp.AcceptedEncodings)
	lw := &loggingWriter{ResponseWriter: writer, s: s, r: request, st: time.Now()}
	defer lw.Close()
	response, err := s.callHandler(request, lw)
	if err != nil {
		response = s.LogError(lw.r, err, nil)
	}
	if response != nil {
		for k, v := range response.Headers() {
			lw.Header().Set(k, v)
		}
		ae := request.Header.Get("Accept-Encoding")
		r := bytes.NewReader(response.Bytes())
		if response.Status() >= 300 {
			// don't compress errors
			ae = ""
		}
		if err := compresshttp.CompressResponse(r, ae, lw, response.Status()); err != nil {
			response = s.LogError(lw.r, err, nil)
			writeResponse(lw, response)
		}
	}
}

func (s *Server) Close() error {
	if s.closeCh != nil {
		close(s.closeCh)
		s.closeCh = nil
	}
	for _, t := range s.tokens {
		t.Close()
	}
	return nil
}

func (s *Server) ReopenLogger() error {
	if s.Config.Server.LogFile == "" {
		return nil
	}
	f, err := os.OpenFile(s.Config.Server.LogFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		return err
	}
	s.logMu.Lock()
	defer s.logMu.Unlock()
	isologger.SetOutput(s.ErrorLog, f, isologger.RFC3339Milli)
	if s.closeLog != nil {
		s.closeLog.Close()
	}
	s.closeLog = f
	return nil
}

func New(config *config.Config, force bool) (*Server, error) {
	closed := make(chan bool)
	s := &Server{
		Config:   config,
		Closed:   closed,
		closeCh:  closed,
		ErrorLog: log.New(os.Stderr, "", 0),
		tokens:   make(map[string]*worker.WorkerToken),
	}
	if err := s.ReopenLogger(); err != nil {
		return nil, fmt.Errorf("failed to open logfile: %s", err)
	}
	for _, name := range config.ListServedTokens() {
		tok, err := worker.New(config, name)
		if err != nil {
			for _, t := range s.tokens {
				t.Close()
			}
			return nil, err
		}
		s.tokens[name] = tok
	}
	if err := s.startHealthCheck(force); err != nil {
		return nil, err
	}
	return s, nil
}
