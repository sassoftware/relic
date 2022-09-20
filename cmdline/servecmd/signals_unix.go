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
	"os"
	"os/signal"
	"syscall"

	"github.com/rs/zerolog/log"
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
			// no longer used
		case !already:
			log.Info().Stringer("signal", sig).Msg("initiating graceful shutdown")
			go func() {
				if err := srv.Close(); err != nil {
					log.Err(err).Msg("failed to shutdown gracefully")
				}
			}()
			already = true
		default:
			log.Warn().Stringer("signal", sig).Msg("shutting down immediately")
			os.Exit(0)
		}
	}
}
