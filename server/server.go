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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"runtime"
	"strings"

	"gerrit-pdt.unx.sas.com/tools/relic.git/config"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/compresshttp"
)

type Server struct {
	Config   *config.Config
	ErrorLog *log.Logger
	Closed   <-chan bool
	closeCh  chan<- bool
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
	closed := lw.CloseNotify()
	go func() {
		if <-closed {
			cancel()
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

func (s *Server) getUserRoles(ctx context.Context, request *http.Request) (context.Context, Response) {
	if request.TLS != nil && len(request.TLS.PeerCertificates) != 0 {
		cert := request.TLS.PeerCertificates[0]
		digest := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
		encoded := hex.EncodeToString(digest[:])
		client, ok := s.Config.Clients[encoded]
		if !ok {
			s.Logr(request, "access denied: unknown fingerprint %s\n", encoded)
			return nil, AccessDeniedResponse
		}
		name := client.Nickname
		if name == "" {
			name = encoded[:12]
		}
		ctx = context.WithValue(ctx, ctxClientName, name)
		ctx = context.WithValue(ctx, ctxRoles, client.Roles)
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
	lw := &loggingWriter{ResponseWriter: writer, s: s, r: request}
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
	return nil
}

func New(config *config.Config, force bool) (*Server, error) {
	var logger *log.Logger
	if config.Server.LogFile != "" {
		f, err := os.OpenFile(config.Server.LogFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			return nil, fmt.Errorf("failed to open logfile: %s", err)
		}
		logger = log.New(f, "", log.Ldate|log.Ltime|log.Lmicroseconds)
	} else {
		logger = log.New(os.Stderr, "", 0)
	}
	closed := make(chan bool)
	s := &Server{
		Config:  config,
		Closed:  closed,
		closeCh: closed,
	}
	s.SetLogger(logger)
	if err := s.startHealthCheck(force); err != nil {
		return nil, err
	}
	return s, nil
}
