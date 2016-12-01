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

	"gerrit-pdt.unx.sas.com/tools/relic.git/p11token"
	"github.com/spf13/cobra"
)

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
	defer func() {
		if err != nil {
			token.Close()
		}
	}()
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
