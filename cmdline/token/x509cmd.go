//
// Copyright (c) SAS Institute Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package token

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/spf13/cobra"

	"github.com/sassoftware/relic/v7/cmdline/shared"
	"github.com/sassoftware/relic/v7/lib/certloader"
	"github.com/sassoftware/relic/v7/lib/x509tools"
)

var (
	argCopyExtensions bool
	argCrossSign      bool
)

var ReqCmd = &cobra.Command{
	Use:   "x509-request",
	Short: "Generate PKCS#10 certificate signing request",
}

var SelfSignCmd = &cobra.Command{
	Use:   "x509-self-sign",
	Short: "Generate self-signed X509 certificate",
}

var SignCsrCmd = &cobra.Command{
	Use:   "x509-sign",
	Short: "Create a X509 certificate from a certificate signing request",
	RunE:  signCsrCmd,
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

	shared.RootCmd.AddCommand(SignCsrCmd)
	addKeyFlags(SignCsrCmd)
	x509tools.AddCertFlags(SignCsrCmd)
	SignCsrCmd.Flags().BoolVar(&argCopyExtensions, "copy-extensions", false, "Copy extensions verbabim from CSR")
	SignCsrCmd.Flags().BoolVar(&argCrossSign, "cross-sign", false, "Input is an existing certificate (implies --copy-extensions)")
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
	if ckaID := key.GetID(); len(ckaID) != 0 {
		fmt.Println("CKA_ID:", formatKeyID(ckaID))
	}
	return nil
}

func signCsrCmd(cmd *cobra.Command, args []string) error {
	if len(args) != 1 {
		return errors.New("expected a CSR file as input")
	}
	csr, err := ioutil.ReadFile(args[0])
	if err != nil {
		return err
	}
	key, err := openKey(argKeyName)
	if err != nil {
		return err
	}
	parsedCert := key.Certificate()
	certPath := key.Config().X509Certificate
	if certPath == "" && len(parsedCert) == 0 {
		return errors.New("token key has no x509 certificate")
	}
	cert, err := certloader.LoadTokenCertificates(key, certPath, "", parsedCert)
	if err != nil {
		return err
	}
	if argCrossSign {
		result, err := x509tools.CrossSign(csr, rand.Reader, key, cert.Leaf)
		if err != nil {
			return err
		}
		os.Stdout.WriteString(result)
	} else {
		result, err := x509tools.SignCSR(csr, rand.Reader, key, cert.Leaf, argCopyExtensions)
		if err != nil {
			return err
		}
		os.Stdout.WriteString(result)
	}
	return nil
}
