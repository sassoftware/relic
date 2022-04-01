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
	"github.com/spf13/cobra"

	"github.com/sassoftware/relic/v7/cmdline/shared"
)

var RemoteCmd = &cobra.Command{
	Use:   "remote",
	Short: "Commands accessing a remote server",
}

var (
	argKeyName string
	argFile    string
	argOutput  string
)

func init() {
	shared.RootCmd.AddCommand(RemoteCmd)
}
