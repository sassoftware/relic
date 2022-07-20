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

package remotecmd

import (
	"errors"
	"fmt"
	"net/http"
	"os"

	"github.com/sassoftware/relic/v7/cmdline/shared"
	"github.com/sassoftware/relic/v7/config"

	"github.com/spf13/cobra"
)

var LoginCmd = &cobra.Command{
	Use:   "login",
	Short: "Interactively login to the server with single sign-on",
	RunE:  loginCmd,
}

func init() {
	RemoteCmd.AddCommand(LoginCmd)
	LoginCmd.Flags().StringVarP(&argRemoteURL, "url", "u", "", "URL of remote server to register to")
	LoginCmd.Flags().BoolVarP(&argForce, "force", "f", false, "Overwrite existing configuration file")
}

func loginCmd(cmd *cobra.Command, args []string) error {
	if argRemoteURL == "" {
		return errors.New("--url is required")
	}
	if shared.ArgConfig == "" {
		shared.ArgConfig = config.DefaultConfig()
		if shared.ArgConfig == "" {
			return errors.New("unable to determine default config location")
		}
	}
	if fileExists(shared.ArgConfig) && !argForce {
		fmt.Fprintf(os.Stderr, "Config file %s already exists\n", shared.ArgConfig)
		return nil
	}
	shared.CurrentConfig = &config.Config{Remote: &config.RemoteConfig{
		DirectoryURL: argRemoteURL,
		Interactive:  true,
	}}
	// prove auth is working
	if _, err := CallRemote("/list_keys", http.MethodGet, nil, nil); err != nil {
		return shared.Fail(err)
	}
	if err := writeConfigObject(shared.ArgConfig, shared.CurrentConfig, false); err != nil {
		return shared.Fail(err)
	}
	return nil
}
