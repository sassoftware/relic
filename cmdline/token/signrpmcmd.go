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
	"github.com/sassoftware/go-rpmutils"
	"github.com/spf13/cobra"
)

var SignRpmCmd = &cobra.Command{
	Use:   "sign-rpm",
	Short: "Sign a RPM using a PGP key in a token",
	RunE:  signRpmCmd,
}

func init() {
	shared.RootCmd.AddCommand(SignRpmCmd)
	shared.AddDigestFlag(SignRpmCmd)
	addAuditFlags(SignRpmCmd)
	SignRpmCmd.Flags().StringVarP(&argKeyName, "key", "k", "", "Name of key section in config file to use")
	SignRpmCmd.Flags().StringVarP(&argFile, "file", "f", "", "Input RPM file to sign")
	SignRpmCmd.Flags().StringVarP(&argOutput, "output", "o", "", "Output RPM file")
	SignRpmCmd.Flags().BoolVarP(&argPatch, "patch", "p", false, "Make a binary patch instead of writing a RPM")
}

func signRpmCmd(cmd *cobra.Command, args []string) (err error) {
	if argFile == "" {
		return errors.New("--key and --file are required")
	} else if argFile == "-" && !argPatch {
		return errors.New("--file and --output must not be -")
	}
	hash, err := shared.GetDigest()
	if err != nil {
		return err
	}
	config := &rpmutils.SignatureOptions{Hash: hash}
	infile, err := openForPatching()
	if err != nil {
		return shared.Fail(err)
	}
	defer infile.Close()
	key, err := openKey(argKeyName)
	if err != nil {
		return err
	}
	entity, err := pgptoken.KeyFromToken(key)
	if err != nil {
		return shared.Fail(err)
	}
	sig, err := signrpm.Sign(infile, entity.PrivateKey, config)
	if err != nil {
		return shared.Fail(err)
	}
	if err := applyPatch(infile, sig.PatchSet); err != nil {
		return shared.Fail(err)
	}
	fmt.Fprintf(os.Stderr, "Signed %s\n", argFile)
	audit := NewAudit(key, "rpm", hash)
	audit.SetPgpCert(entity)
	audit.SetTimestamp(sig.CreationTime)
	audit["rpm.nevra"] = sig.NEVRA()
	audit["rpm.md5"] = sig.MD5()
	audit["rpm.sha1"] = sig.SHA1()
	return shared.Fail(audit.Commit())
}
