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
	"fmt"
	"os"
	"strings"

	"gerrit-pdt.unx.sas.com/tools/relic.git/config"
	"gerrit-pdt.unx.sas.com/tools/relic.git/p11token"
	"github.com/howeyc/gopass"
	"github.com/spf13/cobra"
)

var RootCmd = &cobra.Command{
	Use: "relic",
}

var (
	argConfig    string
	argFile      string
	argJson      bool
	argKeyName   string
	argOutput    string
	argTokenName string
)

var currentConfig *config.Config
var tokenMap map[string]*p11token.Token

func init() {
	tokenMap = make(map[string]*p11token.Token)
	RootCmd.PersistentFlags().StringVarP(&argConfig, "config", "c", "", "Configuration file")
}

type pinPrompt struct{}

func (pinPrompt) WriteString(value string) {
	fmt.Fprintln(os.Stderr, value)
}

func (pinPrompt) GetPin(tokenName string) (string, error) {
	fmt.Fprintf(os.Stderr, "PIN for token %s: ", tokenName)
	pin, err := gopass.GetPasswd()
	if err != nil {
		return "", err
	}
	return string(pin), nil
}

func initConfig() error {
	if argConfig == "" {
		return errors.New("--config is required")
	}
	config, err := config.ReadFile(argConfig)
	if err != nil {
		return err
	}
	currentConfig = config
	return nil
}

func openToken(tokenName string) (*p11token.Token, error) {
	token, ok := tokenMap[tokenName]
	if ok {
		return token, nil
	}
	err := initConfig()
	if err != nil {
		return nil, err
	}
	token, err = p11token.Open(currentConfig, tokenName, &pinPrompt{})
	if err != nil {
		return nil, err
	}
	tokenMap[tokenName] = token
	return token, nil
}

func openTokenByKey(keyName string) (*p11token.Token, error) {
	err := initConfig()
	if err != nil {
		return nil, err
	}
	keyConf, err := currentConfig.GetKey(keyName)
	if err != nil {
		return nil, err
	}
	token, err := openToken(keyConf.Token)
	if err != nil {
		return nil, err
	}
	return token, nil
}

func openKey(keyName string) (*p11token.Key, error) {
	token, err := openTokenByKey(keyName)
	if err != nil {
		return nil, err
	}
	key, err := token.GetKey(keyName)
	if err != nil {
		token.Close()
		return nil, err
	}
	return key, err
}

func closeTokens() {
	for _, token := range tokenMap {
		token.Close()
	}
}

func formatKeyId(key_id []byte) string {
	chunks := make([]string, len(key_id))
	for i, j := range key_id {
		chunks[i] = fmt.Sprintf("%02x", j)
	}
	return strings.Join(chunks, ":")
}

func Main() {
	defer closeTokens()
	if err := RootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
