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
	"os"

	"gerrit-pdt.unx.sas.com/tools/relic.git/pgptoken"
	"gerrit-pdt.unx.sas.com/tools/relic.git/signrpm"
	"github.com/spf13/cobra"
)

var SignRpmCmd = &cobra.Command{
	Use:   "sign-rpm",
	Short: "Sign a RPM using a PGP key in a token",
	RunE:  signRpmCmd,
}

func init() {
	RootCmd.AddCommand(SignRpmCmd)
	SignRpmCmd.Flags().StringVarP(&argKeyName, "key", "k", "", "name of key section in config file to use")
	SignRpmCmd.Flags().StringVarP(&argFile, "file", "f", "", "Input RPM file to sign")
	SignRpmCmd.Flags().StringVarP(&argOutput, "output", "o", "", "Output RPM file")
	SignRpmCmd.Flags().BoolVarP(&argJson, "json-output", "j", false, "Print signature tags instead of writing a RPM")
}

func signRpmCmd(cmd *cobra.Command, args []string) (err error) {
	if argFile == "" {
		return errors.New("--key and --file are required")
	}
	var rpmfile *os.File
	if argFile == "-" {
		rpmfile = os.Stdin
	} else {
		rpmfile, err = os.Open(argFile)
		if err != nil {
			return
		}
	}
	key, err := openKey(argKeyName)
	if err != nil {
		return err
	}
	packet, err := pgptoken.KeyFromToken(key)
	if err != nil {
		return err
	}
	if argJson {
		info, err := signrpm.SignRpmStream(rpmfile, packet, nil)
		if err != nil {
			return err
		}
		info.Dump(os.Stdout)
	} else {
		if argOutput == "" {
			argOutput = argFile
		}
		info, err := signrpm.SignRpmFile(rpmfile, argOutput, packet, nil)
		if err != nil {
			return err
		}
		info.KeyName = argKeyName
		info.LogTo(os.Stderr)
	}
	return nil
}
