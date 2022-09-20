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
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/sync/errgroup"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog/log"
	"github.com/sassoftware/relic/v7/config"
	"github.com/sassoftware/relic/v7/internal/activation"
	"github.com/sassoftware/relic/v7/internal/zhttp"
	"github.com/sassoftware/relic/v7/lib/certloader"
	"github.com/sassoftware/relic/v7/lib/x509tools"
	"github.com/sassoftware/relic/v7/server"
)

type Daemon struct {
	server     *server.Server
	httpServer *http.Server
	listeners  []net.Listener
	metrics    net.Listener
	addrs      []string
	eg         errgroup.Group
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

func getListener(index uint, laddr string, tconf *tls.Config) (net.Listener, error) {
	listener, err := activation.GetListener(index, "tcp", laddr)
	if err == nil {
		if listener.Addr().Network() != "tcp" {
			return nil, errors.New("inherited a listener but it isn't tcp")
		}
		listener = tls.NewListener(listener, tconf)
	}
	return listener, err
}

func New(config *config.Config, test bool) (*Daemon, error) {
	if err := zhttp.SetupLogging(config.Server.LogLevel, config.Server.LogFile); err != nil {
		return nil, fmt.Errorf("configuring logging: %w", err)
	}
	srv, err := server.New(config)
	if err != nil {
		return nil, err
	}
	httpServer := &http.Server{
		Handler:           srv.Handler(),
		ReadHeaderTimeout: time.Second * time.Duration(config.Server.ReadHeaderTimeout),
		ReadTimeout:       time.Second * time.Duration(config.Server.ReadTimeout),
		WriteTimeout:      time.Second * time.Duration(config.Server.WriteTimeout),
		IdleTimeout:       10 * time.Second,
	}
	// configure TLS listener
	if config.Server.Listen != "" {
		tconf, err := makeTLSConfig(config)
		if err != nil {
			return nil, err
		}
		httpServer.TLSConfig = tconf
		if err := http2.ConfigureServer(httpServer, nil); err != nil {
			return nil, err
		}
	}
	if test {
		srv.Close()
		return nil, nil
	}

	var listeners []net.Listener
	var addrs []string
	var index uint
	// open TLS listener
	if config.Server.Listen != "" {
		listener, err := getListener(index, config.Server.Listen, httpServer.TLSConfig)
		if err != nil {
			return nil, err
		}
		listeners = append(listeners, listener)
		addrs = append(addrs, "https://"+listener.Addr().String())
		index++
	}
	// open plaintext listener
	if config.Server.ListenHTTP != "" {
		httpListener, err := activation.GetListener(index, "tcp", config.Server.ListenHTTP)
		if err != nil {
			return nil, err
		}
		listeners = append(listeners, httpListener)
		addrs = append(addrs, "http://"+httpListener.Addr().String())
		index++
	}
	if len(listeners) == 0 {
		return nil, errors.New("no listeners configured")
	}
	// open metrics listener
	var metricsListener net.Listener
	if config.Server.ListenMetrics != "" {
		metricsListener, err = activation.GetListener(index, "tcp", config.Server.ListenMetrics)
		if err != nil {
			return nil, err
		}
		// index++
	}
	return &Daemon{
		server:     srv,
		httpServer: httpServer,
		listeners:  listeners,
		metrics:    metricsListener,
		addrs:      addrs,
	}, nil
}

func (d *Daemon) Serve() error {
	_ = activation.DaemonReady()
	for _, listener := range d.listeners {
		listener := listener // re-scope to loop
		d.eg.Go(func() error {
			err := d.httpServer.Serve(listener)
			if err == http.ErrServerClosed {
				err = nil
			}
			return err
		})
	}
	log.Info().Strs("urls", d.addrs).Msg("listening for requests")
	if d.metrics != nil {
		srv := &http.Server{
			Handler:      promhttp.Handler(),
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 10 * time.Second,
			IdleTimeout:  65 * time.Second,
		}
		go func() {
			err := srv.Serve(d.metrics)
			log.Err(err).Msg("metrics listener stopped")
		}()
		log.Info().Str("url", fmt.Sprintf("http://%s/metrics", d.metrics.Addr())).
			Msg("listening for metrics")
	}
	return d.eg.Wait()
}

func (d *Daemon) Close() error {
	// do Shutdown() inside errgroup because it will cause the ongoing Serve()
	// calls to return immediately and we need something to keep blocking until
	// all ongoing requests are done and Shutdown() returns
	d.eg.Go(func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		err := d.httpServer.Shutdown(ctx)
		err2 := d.server.Close()
		if err == nil {
			err = err2
		}
		return err
	})
	return d.eg.Wait()
}
