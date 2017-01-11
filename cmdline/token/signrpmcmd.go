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
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/signrpm"
	"gerrit-pdt.unx.sas.com/tools/relic.git/p11token/pgptoken"
	"github.com/spf13/cobra"
)

var SignRpmCmd = &cobra.Command{
	Use:   "sign-rpm",
	Short: "Sign a RPM using a PGP key in a token",
	RunE:  signRpmCmd,
}

func init() {
	shared.RootCmd.AddCommand(SignRpmCmd)
	SignRpmCmd.Flags().StringVarP(&argKeyName, "key", "k", "", "Name of key section in config file to use")
	SignRpmCmd.Flags().StringVarP(&argFile, "file", "f", "", "Input RPM file to sign")
	SignRpmCmd.Flags().StringVarP(&argOutput, "output", "o", "", "Output RPM file")
	SignRpmCmd.Flags().BoolVarP(&argJson, "json-output", "j", false, "Print signature tags instead of writing a RPM")
	SignRpmCmd.Flags().BoolVarP(&argPatch, "patch", "p", false, "Make a binary patch instead of writing a RPM")
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
	var info *signrpm.SigInfo
	if argJson || argPatch {
		info, err = signrpm.SignRpmStream(rpmfile, packet, nil)
		if err != nil {
			return err
		}
		if argJson {
			info.Dump(os.Stdout)
		} else if argPatch {
			if argOutput == "" || argOutput == "-" {
				if err := info.DumpPatch(os.Stdout); err != nil {
					return err
				}
			} else {
				outfile, err := os.Create(argOutput)
				if err != nil {
					return err
				}
				if err := info.DumpPatch(outfile); err != nil {
					return err
				}
				outfile.Close()
			}
		}
	} else {
		if argOutput == "" {
			argOutput = argFile
		}
		info, err = signrpm.SignRpmFile(rpmfile, argOutput, packet, nil)
		if err != nil {
			return err
		}
	}
	info.KeyName = argKeyName
	fmt.Fprintf(os.Stderr, "%s\n", info)
	return nil
}
