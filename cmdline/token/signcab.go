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
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/cabfile"
	"github.com/spf13/cobra"
)

var SignCabCmd = &cobra.Command{
	Use:   "sign-cab",
	Short: "Sign a cabinet file using a token",
	RunE:  signCabCmd,
}

func init() {
	shared.RootCmd.AddCommand(SignCabCmd)
	shared.AddDigestFlag(SignCabCmd)
	SignCabCmd.Flags().StringVarP(&argKeyName, "key", "k", "", "Name of key section in config file to use")
	SignCabCmd.Flags().StringVarP(&argFile, "file", "f", "", "Input file to sign")
	SignCabCmd.Flags().StringVarP(&argOutput, "output", "o", "", "Output file. Defaults to same as input.")
	SignCabCmd.Flags().BoolVar(&argPatch, "patch", false, "Output a binary patch instead")
}

func signCabCmd(cmd *cobra.Command, args []string) (err error) {
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
	digest, err := cabfile.Digest(infile, hash)
	if err != nil {
		return shared.Fail(err)
	}
	psd, err := authenticode.SignCabImprint(digest.Imprint, hash, key, certs)
	if err != nil {
		return shared.Fail(err)
	}
	pkcs, err := timestampPkcs(psd, key, certs, hash, true)
	if err != nil {
		return shared.Fail(err)
	}
	patch := digest.MakePatch(pkcs)
	if err := applyPatch(infile, patch); err != nil {
		return shared.Fail(err)
	}
	fmt.Fprintln(os.Stderr, "Signed", argFile)
	audit := NewAudit(key, "cab", hash)
	audit.SetX509Cert(certs[0])
	return PublishAudit(audit)
}
