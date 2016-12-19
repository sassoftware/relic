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

	"gerrit-pdt.unx.sas.com/tools/relic.git/cmdline/shared"
	"gerrit-pdt.unx.sas.com/tools/relic.git/p11token"
	"gerrit-pdt.unx.sas.com/tools/relic.git/p11token/pgptoken"
	"github.com/howeyc/gopass"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/openpgp"
)

var ImportPgpCmd = &cobra.Command{
	Use:   "pgp-import",
	Short: "Import PGP key to token",
	RunE:  importPgpCmd,
}

func init() {
	shared.RootCmd.AddCommand(ImportPgpCmd)
	ImportPgpCmd.Flags().StringVarP(&argKeyName, "key", "k", "", "Name of key section in config file to use")
	ImportPgpCmd.Flags().StringVarP(&argFile, "file", "f", "", "PGP private key file to import (armored or binary)")
}

func readPrivateKey(path string) (*openpgp.Entity, error) {
	entity, err := pgptoken.ReadEntity(path)
	if err != nil {
		return nil, err
	}
	if entity.PrivateKey == nil {
		return nil, errors.New("File must contain a private key")
	}
	fmt.Fprintln(os.Stderr, "Key fingerprint:", entity.PrimaryKey.KeyIdString())
	for name := range entity.Identities {
		fmt.Fprintln(os.Stderr, "UID:", name)
	}
	fmt.Fprintln(os.Stderr, "")
	if entity.PrivateKey.Encrypted {
		os.Stderr.WriteString("Passphrase for key: ")
		keypass, err := gopass.GetPasswd()
		if err != nil {
			return nil, err
		}
		err = entity.PrivateKey.Decrypt(keypass)
		if err != nil {
			return nil, err
		}
	}
	return entity, nil
}

func importPgpCmd(cmd *cobra.Command, args []string) error {
	if argFile == "" {
		return errors.New("--file is required")
	}
	entity, err := readPrivateKey(argFile)
	if err != nil {
		return err
	}
	token, err := openTokenByKey(argKeyName)
	if err != nil {
		return err
	}
	_, err = token.GetKey(argKeyName)
	if err == nil {
		return errors.New("An object with that label already exists in the token")
	} else if _, ok := err.(p11token.KeyNotFoundError); !ok {
		return err
	}
	key, err := token.Import(argKeyName, entity.PrivateKey.PrivateKey)
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Token CKA_ID: ", formatKeyId(key.GetId()))
	return nil
}
