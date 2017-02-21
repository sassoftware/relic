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

package remotecmd

import (
	"errors"
	"io"
	"net/url"
	"os"

	"gerrit-pdt.unx.sas.com/tools/relic.git/cmdline/shared"
	"github.com/spf13/cobra"
)

var GetKeyCmd = &cobra.Command{
	Use:   "get-key",
	Short: "Get a public key certificate from the remote server",
	RunE:  getKeyCmd,
}

func init() {
	RemoteCmd.AddCommand(GetKeyCmd)
}

func getKeyCmd(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return errors.New("Specify one or more key names. See also 'list-keys'.")
	}
	for _, keyName := range args {
		response, err := CallRemote("keys/"+url.PathEscape(keyName), "GET", nil, nil)
		if err != nil {
			return shared.Fail(err)
		}
		if _, err := io.Copy(os.Stdout, response.Body); err != nil {
			return shared.Fail(err)
		}
		response.Body.Close()
	}
	return nil
}
