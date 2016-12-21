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
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"log"
	"net/http"
	"runtime"

	"gerrit-pdt.unx.sas.com/tools/relic.git/config"
)

type Handler interface {
	Handle(*http.Request) (Response, error)
}

type Server struct {
	Config   *config.Config
	Handlers map[string]Handler
}

func (s *Server) callHandler(request *http.Request) (response Response, err error) {
	defer func() {
		if caught := recover(); caught != nil {
			const size = 64 << 10
			buf := make([]byte, size)
			buf = buf[:runtime.Stack(buf, false)]
			s.Logf("Unhandled exception from client %s: %s\n%s\n", GetClientIP(request), caught, buf)
			response = ErrorResponse(http.StatusInternalServerError)
			err = nil
		}
	}()
	ctx := request.Context()
	ctx, errResponse := s.getUserRoles(ctx, request)
	if errResponse != nil {
		return errResponse, nil
	}
	request = request.WithContext(ctx)
	handler, ok := s.Handlers[request.URL.Path]
	if !ok {
		return ErrorResponse(http.StatusNotFound), nil
	}
	return handler.Handle(request)
}

func (s *Server) getUserRoles(ctx context.Context, request *http.Request) (context.Context, Response) {
	if request.TLS == nil {
		return nil, StringResponse(http.StatusBadRequest, "Retry request using TLS")
	}
	if len(request.TLS.PeerCertificates) == 0 {
		return nil, StringResponse(http.StatusBadRequest, "Invalid client certificate")
	}
	cert := request.TLS.PeerCertificates[0]
	digest := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	encoded := hex.EncodeToString(digest[:])
	client, ok := s.Config.Clients[encoded]
	if !ok {
		s.Logf("Denied access to unknown client %s with fingerprint %s\n", GetClientIP(request), encoded)
		return nil, AccessDeniedResponse
	}
	ctx = context.WithValue(ctx, ctxClientName, client.Nickname)
	ctx = context.WithValue(ctx, ctxRoles, client.Roles)
	return ctx, nil
}

func (s *Server) CheckKeyAccess(request *http.Request, keyName string) bool {
	if s.Config.Keys == nil {
		return false
	}
	key, ok := s.Config.Keys[keyName]
	if !ok {
		return false
	}
	clientRoles := GetClientRoles(request)
	if !ok {
		return false
	}
	for _, keyRole := range key.Roles {
		for _, clientRole := range clientRoles {
			if keyRole == clientRole {
				return true
			}
		}
	}
	return false
}

func (s *Server) Logf(format string, args ...interface{}) {
	log.Printf(format, args...)
}

func (s *Server) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	response, err := s.callHandler(request)
	if err != nil {
		s.Logf("Unhandled exception from client %s: %s\n", GetClientIP(request), err)
		response = ErrorResponse(http.StatusInternalServerError)
	}
	response.Write(writer)
}

func (s *Server) makeTlsConfig() (*tls.Config, error) {
	tlscert, err := tls.LoadX509KeyPair(s.Config.Server.CertFile, s.Config.Server.KeyFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates:             []tls.Certificate{tlscert},
		PreferServerCipherSuites: true,
		SessionTicketsDisabled:   true,
		ClientAuth:               tls.RequireAnyClientCert,
		MinVersion:               tls.VersionTLS12,
	}, nil
}

func New(config *config.Config) *Server {
	server := &Server{
		Config:   config,
		Handlers: make(map[string]Handler),
	}
	addHomeHandler(server)
	addSignToolHandler(server)
	addSignRpmHandler(server)
	return server
}

func (s *Server) Serve() error {
	tconf, err := s.makeTlsConfig()
	if err != nil {
		return err
	}
	listener, err := tls.Listen("tcp", s.Config.Server.Listen, tconf)
	if err != nil {
		return err
	}
	httpServer := &http.Server{Handler: s}
	return httpServer.Serve(listener)
}
