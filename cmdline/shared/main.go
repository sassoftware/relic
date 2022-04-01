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

package shared

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/sassoftware/relic/v7/config"
)

var (
	ArgConfig     string
	ArgDebug      uint32
	CurrentConfig *config.Config

	argVersion bool
)

var lateHooks []func()

var RootCmd = &cobra.Command{
	Use:              "relic",
	PersistentPreRun: showVersion,
	RunE:             bailUnlessVersion,
}

func init() {
	RootCmd.PersistentFlags().StringVarP(&ArgConfig, "config", "c", "", "Configuration file")
	RootCmd.PersistentFlags().BoolVar(&argVersion, "version", false, "Show version and exit")
	RootCmd.PersistentFlags().Uint32VarP(&ArgDebug, "debug", "d", 0, "Log additional diagnostic data. (0-9)")
}

func showVersion(cmd *cobra.Command, args []string) {
	if argVersion {
		fmt.Printf("relic version %s (%s)\n", config.Version, config.Commit)
		os.Exit(0)
	}
}

func bailUnlessVersion(cmd *cobra.Command, args []string) error {
	if !argVersion {
		return errors.New("Expected a command")
	}
	return nil
}

func AddLateHook(f func()) {
	lateHooks = append(lateHooks, f)
}

func Main() {
	for _, f := range lateHooks {
		f()
	}
	if err := RootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
