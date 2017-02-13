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
	"io/ioutil"
	"os"

	"gerrit-pdt.unx.sas.com/tools/relic.git/cmdline/shared"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/certloader"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/passprompt"
	"gerrit-pdt.unx.sas.com/tools/relic.git/p11token"
	"github.com/spf13/cobra"
)

var ImportKeyCmd = &cobra.Command{
	Use:   "import-key",
	Short: "Import a private key to a token",
	RunE:  importKeyCmd,
}

func init() {
	shared.RootCmd.AddCommand(ImportKeyCmd)
	ImportKeyCmd.Flags().StringVarP(&argKeyName, "key", "k", "", "Name of key section in config file to use")
	ImportKeyCmd.Flags().StringVarP(&argToken, "token", "t", "", "Name of token to import key to")
	ImportKeyCmd.Flags().StringVarP(&argLabel, "label", "l", "", "Label to attach to imported key")
	ImportKeyCmd.Flags().StringVarP(&argFile, "file", "f", "", "Private key file to import: PEM, DER, or PGP")
}

func importKeyCmd(cmd *cobra.Command, args []string) error {
	if argFile == "" {
		return errors.New("--file is required")
	}
	blob, err := ioutil.ReadFile(argFile)
	if err != nil {
		return shared.Fail(err)
	}
	privKey, err := certloader.ParseAnyPrivateKey(blob, &passprompt.PasswordPrompt{})
	if err != nil {
		return shared.Fail(err)
	}
	keyConf, err := newKeyConfig()
	if err != nil {
		return err
	}
	token, err := openToken(keyConf.Token)
	if err != nil {
		return shared.Fail(err)
	}
	_, err = token.GetKey(argKeyName)
	if err == nil {
		return errors.New("An object with that label already exists in the token")
	} else if _, ok := err.(p11token.KeyNotFoundError); !ok {
		return err
	}
	key, err := token.Import(argKeyName, privKey)
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Token CKA_ID: ", formatKeyId(key.GetId()))
	return nil
}
