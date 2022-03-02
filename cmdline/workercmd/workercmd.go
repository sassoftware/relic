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
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/sassoftware/relic/cmdline/shared"
	"github.com/sassoftware/relic/internal/activation"
	"github.com/sassoftware/relic/internal/activation/activatecmd"
	"github.com/sassoftware/relic/token/open"
	"github.com/spf13/cobra"
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
	log.SetFlags(0)
	if len(args) != 2 {
		log.Fatalln("invalid argument")
	}
	shared.ArgConfig = args[0]
	tokenName := args[1]
	if err := runWorker(tokenName); err != nil {
		log.Fatalf("error: worker for token \"%s\": %+v", tokenName, err)
	}
}

func runWorker(tokenName string) error {
	if err := shared.InitConfig(); err != nil {
		return err
	}
	cookie, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		return err
	}
	lis, err := activation.GetListener(0, "tcp", "")
	if err != nil {
		return err
	}
	tok, err := open.Token(shared.CurrentConfig, tokenName, nil)
	if err != nil {
		return err
	}
	handler := &handler{
		token:  tok,
		cookie: cookie,
		keys:   make(map[string]cachedKey),
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
