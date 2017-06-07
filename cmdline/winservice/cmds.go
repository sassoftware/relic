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

package winservice

import (
	"github.com/sassoftware/relic/cmdline/servecmd"
	"github.com/sassoftware/relic/cmdline/shared"
	"github.com/spf13/cobra"
)

var ServiceCmd = &cobra.Command{
	Use:   "service",
	Short: "Register as a Windows service",
}

var DebugCmd = &cobra.Command{
	Use:   "debug",
	Short: "Run the Windows service in command-line debug mode",
	RunE:  debugCmd,
}

func init() {
	shared.RootCmd.AddCommand(ServiceCmd)
	ServiceCmd.AddCommand(DebugCmd)
}

func debugCmd(cmd *cobra.Command, args []string) error {
	return servecmd.RunService(true)
}
