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
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sassoftware/relic/v7/cmdline/shared"
	"github.com/sassoftware/relic/v7/config"
	"github.com/sassoftware/relic/v7/token"
	"github.com/sassoftware/relic/v7/token/open"
)

var TokenCmd = &cobra.Command{
	Use:   "token",
	Short: "View and manipulate token objects",
}

var TokensCmd = &cobra.Command{
	Use:   "list",
	Short: "List tokens provided by a driver",
	RunE:  tokensCmd,
}

var ContentsCmd = &cobra.Command{
	Use:   "contents",
	Short: "List keys in a token",
	RunE:  contentsCmd,
}

var (
	argType     string
	argProvider string
	argId       string
	argValues   bool
)

func init() {
	shared.RootCmd.AddCommand(TokenCmd)
	TokenCmd.PersistentFlags().StringVarP(&argToken, "token", "t", "", "Name of token")
	TokenCmd.PersistentFlags().StringVar(&argProvider, "provider", "", "Provider module path")

	TokenCmd.AddCommand(TokensCmd)

	TokenCmd.AddCommand(ContentsCmd)
	ContentsCmd.Flags().StringVarP(&argLabel, "label", "l", "", "Display objects with this label only")
	ContentsCmd.Flags().StringVarP(&argId, "id", "i", "", "Display objects with this ID only")
	ContentsCmd.Flags().BoolVarP(&argValues, "values", "v", false, "Show contents of objects")

	shared.AddLateHook(addProviderTypeHelp) // deferred so token providers can init()
}

func addProviderTypeHelp() {
	var listable []string
	for ptype := range token.Listers {
		listable = append(listable, ptype)
	}
	sort.Strings(listable)
	TokenCmd.PersistentFlags().StringVar(&argType, "type", "", fmt.Sprintf("Provider type (%s)", strings.Join(listable, ", ")))
}

func tokensCmd(cmd *cobra.Command, args []string) error {
	if argToken == "" && (argType == "" || argProvider == "") {
		return errors.New("--token, or --type and --provider, are required")
	}
	if err := shared.InitConfig(); err != nil {
		return err
	}
	if argToken != "" {
		tokenConf, err := shared.CurrentConfig.GetToken(argToken)
		if err != nil {
			return err
		}
		if argType == "" {
			argType = tokenConf.Type
		}
		if argProvider == "" {
			argProvider = tokenConf.Provider
		}
	}
	return shared.Fail(open.List(argType, argProvider, os.Stdout))
}

func contentsCmd(cmd *cobra.Command, args []string) error {
	if argToken == "" && (argType == "" || argProvider == "") {
		return errors.New("--token, or --type and --provider, are required")
	}
	if err := shared.InitConfig(); err != nil {
		return err
	}
	var tokenConf *config.TokenConfig
	if argToken != "" {
		var err error
		tokenConf, err = shared.CurrentConfig.GetToken(argToken)
		if err != nil {
			return err
		}
	} else {
		argToken = ":new-token:"
		tokenConf = shared.CurrentConfig.NewToken(argToken)
	}
	if argType != "" {
		tokenConf.Type = argType
	}
	if argProvider != "" {
		tokenConf.Provider = argProvider
	}
	tok, err := openToken(argToken)
	if err != nil {
		return err
	}
	return shared.Fail(tok.ListKeys(token.ListOptions{
		Output: os.Stdout,
		Label:  argLabel,
		ID:     argId,
		Values: argValues,
	}))
}
