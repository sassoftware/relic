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
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/sassoftware/relic/v7/cmdline/shared"
	"github.com/sassoftware/relic/v7/internal/activation"
	"github.com/sassoftware/relic/v7/internal/activation/activatecmd"
	"github.com/sassoftware/relic/v7/internal/zhttp"
	"github.com/sassoftware/relic/v7/token/open"
	"github.com/sassoftware/relic/v7/token/tokencache"
)

func init() {
	AddWorkerCommand(shared.RootCmd)
}

func AddWorkerCommand(parent *cobra.Command) {
	wc := &cobra.Command{
		Use:    "worker",
		Run:    worker,
		Hidden: true,
	}
	parent.AddCommand(wc)
}

func worker(cmd *cobra.Command, args []string) {
	if len(args) != 2 {
		log.Fatal().Msg("invalid argument")
	}
	shared.ArgConfig = args[0]
	tokenName := args[1]
	if err := runWorker(tokenName); err != nil {
		log.Fatal().Msgf("worker stopping for token %s", tokenName)
	}
}

func runWorker(tokenName string) error {
	if err := shared.InitConfig(); err != nil {
		return err
	}
	cookie, err := io.ReadAll(os.Stdin)
	if err != nil {
		return err
	}
	lis, err := activation.GetListener(0, "tcp", "")
	if err != nil {
		return err
	}
	cfg := shared.CurrentConfig
	tok, err := open.Token(cfg, tokenName, nil)
	if err != nil {
		return err
	}
	if err := zhttp.SetupLogging(cfg.Server.LogLevel, cfg.Server.LogFile); err != nil {
		return fmt.Errorf("configuring logging: %w", err)
	}
	log.Logger.UpdateContext(func(c zerolog.Context) zerolog.Context {
		return c.Str("token", tokenName).Int("pid", os.Getpid())
	})
	tconf := tok.Config()
	if tconf.RateLimit != 0 {
		tok = tokencache.NewLimiter(tok, tconf.RateLimit, tconf.RateBurst)
	}
	expiry := time.Second * time.Duration(cfg.Server.TokenCacheSeconds)
	handler := &handler{
		token:  tokencache.New(tok, expiry),
		cookie: cookie,
	}
	srv := &http.Server{Handler: handler}
	wg := new(sync.WaitGroup)
	handler.shutdown = func() {
		// keep the main goroutine from exiting until all requests are served
		wg.Add(1)
		// notify parent that this process is doomed and to start another one
		_ = activatecmd.DaemonStopping()
		// stop accepting requests and wait for ongoing ones to finish
		_ = srv.Shutdown(context.Background())
		wg.Done()
	}
	go handler.watchSignals()
	go handler.healthCheck()
	_ = activation.DaemonReady()
	err = srv.Serve(lis)
	if err == http.ErrServerClosed {
		err = nil
	}
	wg.Wait() // wait for shutdown to finish
	return err
}

func (h *handler) watchSignals() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT,
	)
	<-ch
	signal.Stop(ch)
	h.shutdown()
}
