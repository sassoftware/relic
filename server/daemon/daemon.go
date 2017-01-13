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

package daemon

import (
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"

	"gerrit-pdt.unx.sas.com/tools/relic.git/config"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/x509tools"
	"gerrit-pdt.unx.sas.com/tools/relic.git/server"
	"gerrit-pdt.unx.sas.com/tools/relic.git/server/activation"
	"github.com/braintree/manners"
	"golang.org/x/net/http2"
)

type Daemon struct {
	server   *server.Server
	graceful *manners.GracefulServer
	listener net.Listener
}

func makeTlsConfig(config *config.Config) (*tls.Config, error) {
	tlscert, err := x509tools.LoadX509KeyPair(config.Server.CertFile, config.Server.KeyFile)
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

func getListener(laddr string, tconf *tls.Config) (net.Listener, error) {
	listener, err := activation.GetListener(0, laddr)
	if err == nil {
		if listener.Addr().Network() != "tcp" {
			return nil, errors.New("inherited a listener but it isn't tcp")
		}
		listener = tls.NewListener(listener, tconf)
	}
	return listener, err
}

func New(config *config.Config) (*Daemon, error) {
	srv, err := server.New(config)
	if err != nil {
		return nil, err
	}
	tconf, err := makeTlsConfig(config)
	if err != nil {
		return nil, err
	}
	listener, err := getListener(config.Server.Listen, tconf)
	if err != nil {
		return nil, err
	}
	httpServer := &http.Server{
		Handler:   srv,
		ErrorLog:  srv.ErrorLog,
		TLSConfig: tconf,
	}
	if err := http2.ConfigureServer(httpServer, nil); err != nil {
		return nil, err
	}
	graceful := manners.NewWithServer(httpServer)
	return &Daemon{
		server:   srv,
		graceful: graceful,
		listener: listener,
	}, nil
}

func (d *Daemon) SetOutput(w io.Writer) {
	logger := log.New(w, "", 0)
	d.server.ErrorLog = logger
	d.graceful.ErrorLog = logger
}

func (d *Daemon) Serve() error {
	activation.DaemonReady()
	return d.graceful.Serve(d.listener)
}

func (d *Daemon) Close() {
	d.graceful.Close()
}
