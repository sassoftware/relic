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

package token

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/sassoftware/relic/v7/cmdline/shared"
)

var PingCmd = &cobra.Command{
	Use:   "ping",
	Short: "Check whether a token is working",
	RunE:  pingCmd,
}

func init() {
	shared.RootCmd.AddCommand(PingCmd)
	PingCmd.Flags().StringVarP(&argToken, "token", "t", "", "Name of token section in config file to use")
}

func pingCmd(cmd *cobra.Command, args []string) error {
	token, err := openToken(argToken)
	if err != nil {
		return shared.Fail(err)
	}
	if err := token.Ping(context.Background()); err != nil {
		return shared.Fail(err)
	} else {
		fmt.Println("OK")
	}
	return nil
}
