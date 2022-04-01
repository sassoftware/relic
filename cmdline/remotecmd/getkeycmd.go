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
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/url"
	"os"

	"github.com/spf13/cobra"

	"github.com/sassoftware/relic/v7/cmdline/shared"
)

var GetKeyCmd = &cobra.Command{
	Use:   "get-key",
	Short: "Get a public key certificate from the remote server",
	RunE:  getKeyCmd,
}

func init() {
	RemoteCmd.AddCommand(GetKeyCmd)
}

type keyInfo struct {
	X509Certificate string
	PGPCertificate  string
}

func getKeyInfo(keyName string) (keyInfo, error) {
	response, err := CallRemote("keys/"+url.PathEscape(keyName), "GET", nil, nil)
	if err != nil {
		return keyInfo{}, err
	}
	blob, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return keyInfo{}, err
	}
	response.Body.Close()
	var info keyInfo
	if err := json.Unmarshal(blob, &info); err != nil {
		return keyInfo{}, err
	}
	return info, nil
}

func getKeyCmd(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return errors.New("specify one or more key names. See also 'list-keys'")
	}
	for _, keyName := range args {
		info, err := getKeyInfo(keyName)
		if err != nil {
			return shared.Fail(err)
		}
		os.Stdout.WriteString(info.X509Certificate)
		os.Stdout.WriteString(info.PGPCertificate)
	}
	return nil
}
