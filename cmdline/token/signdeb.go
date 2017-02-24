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
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/signdeb"
	"gerrit-pdt.unx.sas.com/tools/relic.git/p11token/pgptoken"
	"github.com/spf13/cobra"
)

var SignDebCmd = &cobra.Command{
	Use:   "sign-deb",
	Short: "Sign a Debian package using a key in a token",
	RunE:  signDebCmd,
}

var argRole string

func init() {
	shared.RootCmd.AddCommand(SignDebCmd)
	shared.AddDigestFlag(SignDebCmd)
	SignDebCmd.Flags().StringVarP(&argKeyName, "key", "k", "", "Name of key section in config file to use")
	SignDebCmd.Flags().StringVarP(&argFile, "file", "f", "", "Input file to sign")
	SignDebCmd.Flags().StringVarP(&argOutput, "output", "o", "", "Output file")
	SignDebCmd.Flags().BoolVarP(&argPatch, "patch", "p", false, "Write a binary patch instead of an updated file")
	SignDebCmd.Flags().StringVarP(&argRole, "role", "r", "builder", "Debian signing role: origin, maint, archive, etc.")
}

func signDebCmd(cmd *cobra.Command, args []string) (err error) {
	if argFile == "" {
		return errors.New("--key and --file are required")
	}
	hash, err := shared.GetDigest()
	if err != nil {
		return err
	}
	infile, err := openForPatching()
	if err != nil {
		return err
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
	sig, err := signdeb.Sign(infile, entity, hash, argRole)
	if err != nil {
		return shared.Fail(err)
	}
	if err := applyPatch(infile, sig.PatchSet); err != nil {
		return shared.Fail(err)
	}
	fmt.Fprintf(os.Stderr, "Signed %s\n", argFile)
	audit := NewAudit(key, "deb", hash)
	audit.SetPgpCert(entity)
	audit.SetTimestamp(sig.CreationTime)
	audit.Attributes["deb.name"] = sig.Info.Package
	audit.Attributes["deb.version"] = sig.Info.Version
	audit.Attributes["deb.arch"] = sig.Info.Arch
	return PublishAudit(audit)
}
