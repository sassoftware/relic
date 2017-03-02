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
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/authenticode"
	"github.com/spf13/cobra"
)

var SignPsCmd = &cobra.Command{
	Use:   "sign-ps",
	Short: "Sign a powershell file using a token",
	RunE:  signPsCmd,
}

var argPsStyle string

func init() {
	shared.RootCmd.AddCommand(SignPsCmd)
	shared.AddDigestFlag(SignPsCmd)
	SignPsCmd.Flags().StringVarP(&argKeyName, "key", "k", "", "Name of key section in config file to use")
	SignPsCmd.Flags().StringVarP(&argFile, "file", "f", "", "Input file to sign")
	SignPsCmd.Flags().StringVarP(&argOutput, "output", "o", "", "Output file. Defaults to same as input.")
	SignPsCmd.Flags().StringVar(&argPsStyle, "ps-style", "", "Powershell file type")
	SignPsCmd.Flags().BoolVar(&argPatch, "patch", false, "Output a binary patch instead")
}

func signPsCmd(cmd *cobra.Command, args []string) (err error) {
	if argFile == "" {
		return errors.New("--key and --file are required")
	} else if !argPatch && (argFile == "-" || argOutput == "-") {
		return errors.New("--file and --output must be paths, not -")
	}
	hash, err := shared.GetDigest()
	if err != nil {
		return err
	}
	if argPsStyle == "" {
		argPsStyle = argFile
	}
	style, ok := authenticode.GetSigStyle(argPsStyle)
	if !ok {
		return shared.Fail(errors.New("unknown powershell style, expected: " + strings.Join(authenticode.AllSigStyles(), " ")))
	}
	infile, err := openForPatching()
	if err != nil {
		return shared.Fail(err)
	}
	defer infile.Close()
	key, err := openKey(argKeyName)
	if err != nil {
		return err
	}
	certs, err := readCerts(key)
	if err != nil {
		return shared.Fail(err)
	}
	digest, err := authenticode.DigestPowershell(infile, style, hash)
	if err != nil {
		return shared.Fail(err)
	}
	psd, err := digest.Sign(key, certs)
	if err != nil {
		return shared.Fail(err)
	}
	pkcs, err := timestampPkcs(psd, key, certs, hash, true)
	if err != nil {
		return shared.Fail(err)
	}
	patch, err := digest.MakePatch(pkcs)
	if err != nil {
		return shared.Fail(err)
	}
	if err := applyPatch(infile, patch); err != nil {
		return shared.Fail(err)
	}
	fmt.Fprintln(os.Stderr, "Signed", argFile)
	audit := NewAudit(key, "ps", hash)
	audit.SetX509Cert(certs[0])
	return PublishAudit(audit)
}
