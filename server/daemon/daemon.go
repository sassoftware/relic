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

package daemon

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"

	"github.com/sassoftware/relic/config"
	"github.com/sassoftware/relic/internal/activation"
	"github.com/sassoftware/relic/lib/certloader"
	"github.com/sassoftware/relic/lib/x509tools"
	"github.com/sassoftware/relic/server"
	"golang.org/x/net/http2"
)

type Daemon struct {
	server     *server.Server
	httpServer *http.Server
	listeners  []net.Listener
	wg         sync.WaitGroup
}

func makeTLSConfig(config *config.Config) (*tls.Config, error) {
	cert, err := certloader.LoadX509KeyPair(config.Server.CertFile, config.Server.KeyFile)
	if err != nil {
		return nil, err
	}
	var keyLog io.Writer
	if klf := os.Getenv("SSLKEYLOGFILE"); klf != "" {
		fmt.Fprintln(os.Stderr, "WARNING: SSLKEYLOGFILE is set! TLS master secrets will be logged.")
		keyLog, err = os.OpenFile(klf, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0666)
		if err != nil {
			return nil, err
		}
	}

	tconf := &tls.Config{
		Certificates:             []tls.Certificate{cert.TLS()},
		PreferServerCipherSuites: true,
		SessionTicketsDisabled:   true,
		ClientAuth:               tls.RequestClientCert,
		MinVersion:               tls.VersionTLS12,
		KeyLogWriter:             keyLog,
	}
	x509tools.SetKeyLogFile(tconf)
	return tconf, nil
}

func getListener(laddr string, tconf *tls.Config) (net.Listener, error) {
	listener, err := activation.GetListener(0, "tcp", laddr)
	if err == nil {
		if listener.Addr().Network() != "tcp" {
			return nil, errors.New("inherited a listener but it isn't tcp")
		}
		listener = tls.NewListener(listener, tconf)
	}
	return listener, err
}

func New(config *config.Config, test bool) (*Daemon, error) {
	srv, err := server.New(config)
	if err != nil {
		return nil, err
	}
	tconf, err := makeTLSConfig(config)
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
	if test {
		srv.Close()
		return nil, nil
	}

	listener, err := getListener(config.Server.Listen, tconf)
	if err != nil {
		return nil, err
	}
	listeners := []net.Listener{listener}
	if config.Server.ListenHTTP != "" {
		httpListener, err := activation.GetListener(1, "tcp", config.Server.ListenHTTP)
		if err != nil {
			return nil, err
		}
		listeners = append(listeners, httpListener)
	}
	return &Daemon{
		server:     srv,
		httpServer: httpServer,
		listeners:  listeners,
	}, nil
}

func (d *Daemon) SetOutput(w io.Writer) {
	d.server.ErrorLog.SetFlags(0)
	d.server.ErrorLog.SetPrefix("")
	d.server.ErrorLog.SetOutput(w)
}

func (d *Daemon) ReopenLogger() error {
	return d.server.ReopenLogger()
}

func (d *Daemon) Serve() error {
	activation.DaemonReady()
	errch := make(chan error, len(d.listeners))
	for _, listener := range d.listeners {
		d.wg.Add(1)
		go func(listener net.Listener) {
			errch <- d.httpServer.Serve(listener)
			d.wg.Done()
		}(listener)
	}
	d.wg.Wait()
	for _ = range d.listeners {
		if err := <-errch; err != nil {
			return err
		}
	}
	return nil
}

func (d *Daemon) Close() error {
	// prevent Serve() from returning until the shutdown completes
	d.wg.Add(1)
	err := d.httpServer.Shutdown(context.Background())
	d.server.Close()
	d.wg.Done()
	return err
}
