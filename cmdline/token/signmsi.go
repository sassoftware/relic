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

	"gerrit-pdt.unx.sas.com/tools/relic.git/cmdline/shared"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/authenticode"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/comdoc"
	"github.com/spf13/cobra"
)

var SignMsiCmd = &cobra.Command{
	Use:   "sign-msi",
	Short: "Sign a PE-COFF executable using a token",
	RunE:  signMsiCmd,
}

var argNoMsiExtended bool

func init() {
	shared.RootCmd.AddCommand(SignMsiCmd)
	shared.AddDigestFlag(SignMsiCmd)
	SignMsiCmd.Flags().StringVarP(&argKeyName, "key", "k", "", "Name of key section in config file to use")
	SignMsiCmd.Flags().StringVarP(&argFile, "file", "f", "", "Input file to sign")
	//SignMsiCmd.Flags().StringVarP(&argOutput, "output", "o", "", "Output file. Defaults to same as input.")
	SignMsiCmd.Flags().BoolVar(&argNoMsiExtended, "no-extended-sig", false, "Don't emit a MsiDigitalSignatureEx digest")
}

func signMsiCmd(cmd *cobra.Command, args []string) (err error) {
	if argFile == "" {
		return errors.New("--key and --file are required")
	} else if argFile == "-" { //|| argOutput == "-" {
		return errors.New("--file and --output must be paths, not -")
	}
	hash, err := shared.GetDigest()
	if err != nil {
		return err
	}
	cdf, err := comdoc.WritePath(argFile)
	if err != nil {
		return shared.Fail(err)
	}
	sum, exsig, err := authenticode.DigestMSI(cdf, hash, !argNoMsiExtended)
	if err != nil {
		return shared.Fail(err)
	}

	key, err := openKey(argKeyName)
	if err != nil {
		return err
	}
	certs, err := readCerts(key)
	if err != nil {
		return shared.Fail(err)
	}
	psd, err := authenticode.SignMSIImprint(sum, hash, key, certs)
	if err != nil {
		return shared.Fail(err)
	}
	pkcs, err := timestampPkcs(psd, key, certs, hash, true)
	if err != nil {
		return shared.Fail(err)
	}
	if err := authenticode.InsertMSISignature(cdf, pkcs, exsig); err != nil {
		return shared.Fail(err)
	}
	if err := cdf.Close(); err != nil {
		return shared.Fail(err)
	}
	return nil
}
