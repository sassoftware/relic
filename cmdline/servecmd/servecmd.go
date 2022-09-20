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
	"errors"
	"fmt"
	"net"
	"net/http"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/sassoftware/relic/v7/cmdline/shared"
	"github.com/sassoftware/relic/v7/server/daemon"

	_ "net/http/pprof"
)

var ServeCmd = &cobra.Command{
	Use:   "serve",
	Short: "Offer signing services over a HTTPS API",
	RunE:  serveCmd,
}

var argTest bool

func init() {
	shared.RootCmd.AddCommand(ServeCmd)
	ServeCmd.Flags().BoolP("force", "f", false, "(ignored)")
	ServeCmd.Flags().BoolVarP(&argTest, "test", "t", false, "Test configuration and exit")
}

func MakeServer() (*daemon.Daemon, error) {
	if err := shared.InitConfig(); err != nil {
		return nil, err
	}
	if shared.CurrentConfig.Server == nil {
		return nil, errors.New("Missing server section in configuration file")
	}
	if shared.CurrentConfig.Clients == nil {
		return nil, errors.New("Missing clients section in configuration file")
	}
	if shared.CurrentConfig.Server.Listen == "" && shared.CurrentConfig.Server.ListenHTTP == "" {
		shared.CurrentConfig.Server.Listen = ":6300"
	}
	if shared.CurrentConfig.Server.Listen != "" {
		if shared.CurrentConfig.Server.KeyFile == "" {
			return nil, errors.New("missing keyfile option in server configuration file")
		}
		if shared.CurrentConfig.Server.CertFile == "" {
			return nil, errors.New("missing certfile option in server configuration file")
		}
	}
	return daemon.New(shared.CurrentConfig, argTest)
}

func listenDebug() error {
	if !shared.CurrentConfig.Server.ListenDebug {
		return nil
	}
	lis, err := net.Listen("tcp", ":0")
	if err != nil {
		return err
	}
	log.Info().Msgf("serving debug info on http://%s/debug/pprof/", lis.Addr())
	go func() {
		// pprof installs itself into the default handler on import
		err := http.Serve(lis, nil)
		log.Err(err).Msg("debug listener stopped")
	}()
	return nil
}

func serveCmd(cmd *cobra.Command, args []string) error {
	// let journald add timestamps
	srv, err := MakeServer()
	if err != nil {
		return shared.Fail(err)
	} else if argTest {
		fmt.Println("OK")
		return nil
	}
	go watchSignals(srv)
	if err := listenDebug(); err != nil {
		return err
	}
	if err := srv.Serve(); err != nil && err != http.ErrServerClosed {
		return shared.Fail(err)
	}
	return nil
}
