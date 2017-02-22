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
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/authenticode"
	"github.com/spf13/cobra"
)

var SignPeCmd = &cobra.Command{
	Use:   "sign-pe",
	Short: "Sign a PE-COFF executable using a token",
	RunE:  signPeCmd,
}

var argPageHashes bool

func init() {
	shared.RootCmd.AddCommand(SignPeCmd)
	shared.AddDigestFlag(SignPeCmd)
	SignPeCmd.Flags().StringVarP(&argKeyName, "key", "k", "", "Name of key section in config file to use")
	SignPeCmd.Flags().StringVarP(&argFile, "file", "f", "", "Input file to sign")
	SignPeCmd.Flags().StringVarP(&argOutput, "output", "o", "", "Output file. Defaults to same as input.")
	SignPeCmd.Flags().BoolVar(&argPageHashes, "page-hashes", false, "Add page hashes to signature")
	SignPeCmd.Flags().BoolVar(&argPatch, "patch", false, "Output a binary patch instead")
}

func signPeCmd(cmd *cobra.Command, args []string) (err error) {
	if argFile == "" {
		return errors.New("--key and --file are required")
	} else if !argPatch && (argFile == "-" || argOutput == "-") {
		return errors.New("--file and --output must be paths, not -")
	}
	hash, err := shared.GetDigest()
	if err != nil {
		return err
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
	digest, err := authenticode.DigestPE(infile, hash, argPageHashes)
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
	if !argPatch {
		if argOutput == "" {
			argOutput = argFile
		}
		f, err := os.OpenFile(argOutput, os.O_RDWR, 0)
		if err != nil {
			return shared.Fail(err)
		}
		defer f.Close()
		if err := authenticode.FixPEChecksum(f); err != nil {
			return shared.Fail(err)
		}
	}
	fmt.Fprintln(os.Stderr, "Signed", argFile)
	return nil
}
