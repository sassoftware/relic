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
	"errors"

	"github.com/sassoftware/relic/cmdline/shared"
	"github.com/sassoftware/relic/server/daemon"
	"github.com/spf13/cobra"
)

var ServeCmd = &cobra.Command{
	Use:   "serve",
	Short: "Offer signing services over a HTTPS API",
	RunE:  serveCmd,
}

var argForce bool

func init() {
	shared.RootCmd.AddCommand(ServeCmd)
	ServeCmd.Flags().BoolVarP(&argForce, "force", "f", false, "Start even if the initial health check fails")
}

func MakeServer() (*daemon.Daemon, error) {
	if err := shared.InitConfig(); err != nil {
		return nil, err
	}
	if shared.CurrentConfig.Server == nil {
		return nil, errors.New("Missing server section in configuration file")
	}
	if shared.CurrentConfig.Server.KeyFile == "" {
		return nil, errors.New("Missing keyfile option in server configuration file")
	}
	if shared.CurrentConfig.Server.CertFile == "" {
		return nil, errors.New("Missing certfile option in server configuration file")
	}
	if shared.CurrentConfig.Clients == nil {
		return nil, errors.New("Missing clients section in configuration file")
	}
	if shared.CurrentConfig.Server.Listen == "" {
		shared.CurrentConfig.Server.Listen = ":6300"
	}
	return daemon.New(shared.CurrentConfig, argForce)
}

func serveCmd(cmd *cobra.Command, args []string) error {
	if runIfService() {
		// windows service
		return nil
	}
	srv, err := MakeServer()
	if err != nil {
		return shared.Fail(err)
	}
	go watchSignals(srv)
	return shared.Fail(srv.Serve())
}
