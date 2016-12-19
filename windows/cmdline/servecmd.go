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

package cmdline

import (
	"errors"

	"gerrit-pdt.unx.sas.com/tools/relic.git/server"
	"gerrit-pdt.unx.sas.com/tools/relic.git/windows/handler"
	"github.com/spf13/cobra"
)

var ServeCmd = &cobra.Command{
	Use:   "serve",
	Short: "Offer signing services over a HTTPS API",
	RunE:  serveCmd,
}

func init() {
	RootCmd.AddCommand(ServeCmd)
}

func serveCmd(cmd *cobra.Command, args []string) error {
	if err := initConfig(); err != nil {
		return err
	}
	if currentConfig.Server == nil {
		return errors.New("Missing server section in configuration file")
	}
	if currentConfig.Server.KeyFile == "" {
		return errors.New("Missing keyfile option in server configuration file")
	}
	if currentConfig.Server.CertFile == "" {
		return errors.New("Missing certfile option in server configuration file")
	}
	if currentConfig.Clients == nil {
		return errors.New("Missing clients section in configuration file")
	}
	if currentConfig.Server.Listen == "" {
		currentConfig.Server.Listen = ":8888"
	}
	srv := server.New(currentConfig)
	handler.AddSignWinHandler(srv)
	return srv.Serve()
}
