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
	"errors"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/spf13/cobra"

	"github.com/sassoftware/relic/v7/cmdline/shared"
	"github.com/sassoftware/relic/v7/lib/certloader"
	"github.com/sassoftware/relic/v7/lib/passprompt"
	"github.com/sassoftware/relic/v7/lib/x509tools"
	"github.com/sassoftware/relic/v7/signers/sigerrors"
)

var ImportKeyCmd = &cobra.Command{
	Use:   "import-key",
	Short: "Import a private key to a token",
	RunE:  importKeyCmd,
}

var argPkcs12 bool

func init() {
	shared.RootCmd.AddCommand(ImportKeyCmd)
	addKeyFlags(ImportKeyCmd)
	ImportKeyCmd.Flags().StringVarP(&argToken, "token", "t", "", "Name of token to import key to")
	ImportKeyCmd.Flags().StringVarP(&argLabel, "label", "l", "", "Label to attach to imported key")
	ImportKeyCmd.Flags().StringVarP(&argFile, "file", "f", "", "Private key file to import: PEM, DER, or PGP")
	ImportKeyCmd.Flags().BoolVar(&argPkcs12, "pkcs12", false, "Import a PKCS12 key and certificate chain")
}

func importKeyCmd(cmd *cobra.Command, args []string) error {
	if argFile == "" {
		return errors.New("--file is required")
	}
	blob, err := ioutil.ReadFile(argFile)
	if err != nil {
		return shared.Fail(err)
	}
	prompt := new(passprompt.PasswordPrompt)
	var cert *certloader.Certificate
	if argPkcs12 {
		var err error
		cert, err = certloader.ParsePKCS12(blob, prompt)
		if err != nil {
			return shared.Fail(err)
		}
	} else {
		privKey, err := certloader.ParseAnyPrivateKey(blob, prompt)
		if err != nil {
			return shared.Fail(err)
		}
		cert = &certloader.Certificate{PrivateKey: privKey}
	}
	keyConf, err := newKeyConfig()
	if err != nil {
		return err
	}
	tok, err := openToken(keyConf.Token)
	if err != nil {
		return shared.Fail(err)
	}
	var didSomething bool
	key, err := tok.GetKey(context.Background(), argKeyName)
	if err == nil {
		if cert.Leaf == nil {
			return errors.New("An object with that label already exists in the token")
		}
		fmt.Fprintln(os.Stderr, "Private key already exists. Attempting to import certificates.")
	} else if _, ok := err.(sigerrors.KeyNotFoundError); !ok {
		return err
	} else {
		key, err = tok.Import(argKeyName, cert.PrivateKey)
		if err != nil {
			return err
		}
		didSomething = true
	}
	if cert.Leaf != nil {
		name := x509tools.FormatSubject(cert.Leaf)
		err := key.ImportCertificate(cert.Leaf)
		if err == sigerrors.ErrExist {
			fmt.Fprintln(os.Stderr, "Certificate already exists:", name)
		} else if err != nil {
			return shared.Fail(fmt.Errorf("importing %s: %w", name, err))
		} else {
			fmt.Fprintln(os.Stderr, "Imported", name)
			didSomething = true
		}
		for _, chain := range cert.Chain() {
			if chain == cert.Leaf {
				continue
			}
			name = x509tools.FormatSubject(chain)
			err = tok.ImportCertificate(chain, keyConf.Label)
			if err == sigerrors.ErrExist {
				fmt.Fprintln(os.Stderr, "Certificate already exists:", name)
			} else if err != nil {
				return shared.Fail(fmt.Errorf("importing %s: %w", name, err))
			} else {
				fmt.Fprintln(os.Stderr, "Imported", name)
				didSomething = true
			}
		}
	}
	if !didSomething {
		return shared.Fail(errors.New("nothing imported"))
	}
	fmt.Fprintln(os.Stderr, "Token CKA_ID: ", formatKeyID(key.GetID()))
	return nil
}
