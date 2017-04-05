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
	"crypto/rand"
	"errors"
	"fmt"
	"os"

	"gerrit-pdt.unx.sas.com/tools/relic.git/cmdline/shared"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/x509tools"
	"github.com/spf13/cobra"
)

var ReqCmd = &cobra.Command{
	Use:   "x509-request",
	Short: "Generate PKCS#10 certificate signing request",
}

var SelfSignCmd = &cobra.Command{
	Use:   "x509-self-sign",
	Short: "Generate self-signed X509 certificate",
}

func init() {
	ReqCmd.RunE = x509Cmd
	shared.RootCmd.AddCommand(ReqCmd)
	addSelectOrGenerateFlags(ReqCmd)
	x509tools.AddRequestFlags(ReqCmd)

	SelfSignCmd.RunE = x509Cmd
	shared.RootCmd.AddCommand(SelfSignCmd)
	addSelectOrGenerateFlags(SelfSignCmd)
	x509tools.AddCertFlags(SelfSignCmd)
}

func x509Cmd(cmd *cobra.Command, args []string) error {
	if x509tools.ArgCommonName == "" {
		return errors.New("--commonName is required")
	}
	key, err := selectOrGenerate()
	if err != nil {
		return err
	}
	var result string
	if cmd == ReqCmd {
		result, err = x509tools.MakeRequest(rand.Reader, key)
	} else {
		result, err = x509tools.MakeCertificate(rand.Reader, key)
	}
	if err != nil {
		return err
	}
	os.Stdout.WriteString(result)
	fmt.Println("CKA_ID:", formatKeyID(key.GetID()))
	return nil
}
