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

package token

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"gerrit-pdt.unx.sas.com/tools/relic.git/cmdline/shared"
	"gerrit-pdt.unx.sas.com/tools/relic.git/p11token"
	"github.com/howeyc/gopass"
	"github.com/spf13/cobra"
)

var (
	argFile      string
	argJson      bool
	argPatch     bool
	argKeyName   string
	argOutput    string
	argTokenName string
)

var tokenMap map[string]*p11token.Token

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

func addSelectOrGenerateFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&argKeyName, "key", "k", "", "Name of key section in config file to use")
	cmd.Flags().UintVar(&argRsaBits, "generate-rsa", 0, "Generate a RSA key of the specified bit size, if needed")
	cmd.Flags().UintVar(&argEcdsaBits, "generate-ecdsa", 0, "Generate an ECDSA key of the specified curve size, if needed")
}

func selectOrGenerate() (key *p11token.Key, err error) {
	token, err := openTokenByKey(argKeyName)
	if err != nil {
		return nil, err
	}
	key, err = token.GetKey(argKeyName)
	if err == nil {
		fmt.Fprintln(os.Stderr, "Using existing key in token")
		return key, nil
	} else if _, ok := err.(p11token.KeyNotFoundError); !ok {
		return nil, err
	}
	fmt.Fprintln(os.Stderr, "Generating a new key in token")
	if argRsaBits != 0 {
		return token.Generate(argKeyName, p11token.CKK_RSA, argRsaBits)
	} else if argEcdsaBits != 0 {
		return token.Generate(argKeyName, p11token.CKK_ECDSA, argEcdsaBits)
	} else {
		return nil, errors.New("No matching key exists, specify --generate-rsa or --generate-ecdsa to generate one")
	}
}

func openToken(tokenName string) (*p11token.Token, error) {
	token, ok := tokenMap[tokenName]
	if ok {
		return token, nil
	}
	err := shared.InitConfig()
	if err != nil {
		return nil, err
	}
	token, err = p11token.Open(shared.CurrentConfig, tokenName, &pinPrompt{})
	if err != nil {
		return nil, err
	}
	if tokenMap == nil {
		tokenMap = make(map[string]*p11token.Token)
	}
	tokenMap[tokenName] = token
	return token, nil
}

func openTokenByKey(keyName string) (*p11token.Token, error) {
	err := shared.InitConfig()
	if err != nil {
		return nil, err
	}
	keyConf, err := shared.CurrentConfig.GetKey(keyName)
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

func formatKeyId(key_id []byte) string {
	chunks := make([]string, len(key_id))
	for i, j := range key_id {
		chunks[i] = fmt.Sprintf("%02x", j)
	}
	return strings.Join(chunks, ":")
}
