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
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/appmanifest"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/atomicfile"
	"github.com/spf13/cobra"
)

var SignAppManifestCmd = &cobra.Command{
	Use:   "sign-app-manifest",
	Short: "Sign a ClickOnce application manifest using a token",
	RunE:  signAppManifestCmd,
}

func init() {
	shared.RootCmd.AddCommand(SignAppManifestCmd)
	shared.AddDigestFlag(SignAppManifestCmd)
	SignAppManifestCmd.Flags().StringVarP(&argKeyName, "key", "k", "", "Name of key section in config file to use")
	SignAppManifestCmd.Flags().StringVarP(&argFile, "file", "f", "", "Input file to sign")
	SignAppManifestCmd.Flags().StringVarP(&argOutput, "output", "o", "", "Output file. Defaults to same as input.")
}

func signAppManifestCmd(cmd *cobra.Command, args []string) (err error) {
	if argFile == "" {
		return errors.New("--key and --file are required")
	}
	hash, err := shared.GetDigest()
	if err != nil {
		return err
	}
	blob, err := shared.ReadFile(argFile)
	if err != nil {
		return shared.Fail(err)
	}
	key, err := openKey(argKeyName)
	if err != nil {
		return err
	}
	cert, err := readCert(key)
	if err != nil {
		return shared.Fail(err)
	}
	signed, err := appmanifest.Sign(blob, key, cert, hash)
	if err != nil {
		return shared.Fail(err)
	}
	if argOutput == "" {
		argOutput = argFile
	}
	if err := atomicfile.WriteFile(argOutput, signed.Signed); err != nil {
		return shared.Fail(err)
	}
	fmt.Fprintln(os.Stderr, "Signed", argFile)
	audit := NewAudit(key, "app-manifest", hash)
	audit.SetX509Cert(cert.Leaf)
	return PublishAudit(audit)
}
