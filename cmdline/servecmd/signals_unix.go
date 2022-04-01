//go:build !windows
// +build !windows

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

package servecmd

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/sassoftware/relic/v7/server/daemon"
)

func watchSignals(srv *daemon.Daemon) {
	ch := make(chan os.Signal, 4)
	signal.Notify(
		ch,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT,
		syscall.SIGUSR1,
		syscall.SIGUSR2,
	)
	already := false
	for {
		sig := <-ch
		switch {
		case sig == syscall.SIGUSR1:
			if err := srv.ReopenLogger(); err != nil {
				log.Printf("Failed to reopen logs: %s", err)
			}
		case !already:
			log.Printf("Received signal %d; shutting down gracefully", sig)
			if err := srv.Close(); err != nil {
				log.Printf("ERROR: failed to shutdown gracefully: %s", err)
			}
			already = true
		default:
			log.Printf("Received signal %d; shutting down immediately", sig)
			os.Exit(0)
		}
	}
}
