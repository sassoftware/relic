// +build !windows

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

package servecmd

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/sassoftware/relic/server/daemon"
)

func watchSignals(srv *daemon.Daemon) {
	ch := make(chan os.Signal, 4)
	signal.Notify(
		ch,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT,
		syscall.SIGUSR2,
	)
	already := false
	for {
		sig := <-ch
		if (sig == syscall.SIGQUIT || sig == syscall.SIGUSR2) && !already {
			log.Printf("Received signal %d; shutting down gracefully", sig)
			srv.Close()
			already = true
		} else {
			log.Printf("Received signal %d; shutting down immediately", sig)
			os.Exit(0)
		}
	}
}
