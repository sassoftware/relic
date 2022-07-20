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
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/sassoftware/relic/v7/config"
	"github.com/sassoftware/relic/v7/internal/authmodel"
	"github.com/sassoftware/relic/v7/internal/realip"
	"github.com/sassoftware/relic/v7/internal/zhttp"
	"github.com/sassoftware/relic/v7/lib/compresshttp"
	"github.com/sassoftware/relic/v7/token/worker"
)

type Server struct {
	Config  *config.Config
	Closed  <-chan bool
	closeCh chan<- bool
	tokens  map[string]*worker.WorkerToken
	auth    authmodel.Authenticator
	realIP  func(http.Handler) http.Handler
}

func (s *Server) Handler() http.Handler {
	r := chi.NewRouter()
	r.Use(s.realIP)
	r.Use(zhttp.LoggingMiddleware())
	r.Use(zhttp.RecoveryMiddleware)
	r.Use(compresshttp.Middleware)
	// unauthenticated methods
	r.Get("/health", s.serveHealth)
	r.Get("/directory", s.serveDirectory)
	// authenticated methods
	a := r.With(authmodel.Middleware(s.auth))
	a.Get("/", handleFunc(s.serveHome))
	a.Get("/list_keys", handleFunc(s.serveListKeys))
	a.Get("/keys/{key}", handleFunc(s.serveGetKey))
	a.Post("/sign", handleFunc(s.serveSign))
	return r
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

func New(config *config.Config) (*Server, error) {
	closed := make(chan bool)
	auth, err := authmodel.New(config)
	if err != nil {
		return nil, fmt.Errorf("configuration authentication: %w", err)
	}
	realIP, err := realip.Middleware(config.Server.TrustedProxies)
	if err != nil {
		return nil, err
	}
	s := &Server{
		Config:  config,
		Closed:  closed,
		closeCh: closed,
		auth:    auth,
		realIP:  realIP,
		tokens:  make(map[string]*worker.WorkerToken),
	}
	// create a worker for each token used by any key
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
	if err := s.startHealthCheck(); err != nil {
		return nil, err
	}
	return s, nil
}
