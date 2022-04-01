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
	"fmt"
	"io/ioutil"

	"github.com/sassoftware/relic/v7/cmdline/shared"

	"github.com/spf13/cobra"
)

var ListKeysCmd = &cobra.Command{
	Use:   "list-keys",
	Short: "List keys available on the remote server",
	RunE:  listKeysCmd,
}

func init() {
	RemoteCmd.AddCommand(ListKeysCmd)
}

func listKeysCmd(cmd *cobra.Command, args []string) error {
	var keyList []string
	response, err := CallRemote("list_keys", "GET", nil, nil)
	if err != nil {
		return shared.Fail(err)
	}
	resbytes, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return shared.Fail(err)
	}
	response.Body.Close()
	err = json.Unmarshal(resbytes, &keyList)
	if err != nil {
		return shared.Fail(err)
	}
	for _, key := range keyList {
		fmt.Println(key)
	}
	return nil
}
