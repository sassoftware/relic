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

package verify

import (
	"crypto/x509"
	"errors"
	"fmt"
	"os"

	"gerrit-pdt.unx.sas.com/tools/relic.git/cmdline/shared"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/authenticode"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/certloader"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/magic"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/openpgp"
)

var VerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify a signed package or executable",
	RunE:  verifyCmd,
}

var (
	argNoIntegrityCheck  bool
	argNoChain           bool
	argAlsoSystem        bool
	argContent           string
	argTrustedCerts      []string
	argIntermediateCerts []string

	trustedCerts      []*x509.Certificate
	trustedPool       *x509.CertPool
	trustedPgp        openpgp.EntityList
	intermediateCerts []*x509.Certificate
)

func init() {
	shared.RootCmd.AddCommand(VerifyCmd)
	VerifyCmd.Flags().BoolVar(&argNoIntegrityCheck, "no-integrity-check", false, "Bypass the integrity check of the file contents and only inspect the signature itself")
	VerifyCmd.Flags().BoolVar(&argNoChain, "no-trust-chain", false, "Do not test whether the signing certificate is trusted")
	VerifyCmd.Flags().BoolVar(&argAlsoSystem, "system-store", false, "When --cert is used, append rather than replace the system trust store")
	VerifyCmd.Flags().StringVar(&argContent, "content", "", "Specify file containing contents for detached signatures")
	VerifyCmd.Flags().StringArrayVar(&argTrustedCerts, "cert", nil, "Add a trusted root certificate (PEM, DER, PKCS#7, or PGP)")
	VerifyCmd.Flags().StringArrayVar(&argIntermediateCerts, "intermediate-cert", nil, "Add an extra cert to help build the trust chain")
}

func verifyCmd(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return errors.New("Expected 1 or more files")
	}
	if err := loadCerts(); err != nil {
		return err
	}
	rc := 0
	for _, path := range args {
		if err := verifyOne(path); err != nil {
			fmt.Printf("%s ERROR: %s\n", path, err)
			rc = 1
		}
	}
	if rc != 0 {
		fmt.Fprintln(os.Stderr, "ERROR: 1 or more files did not validate")
	}
	os.Exit(rc)
	return nil
}

func verifyOne(path string) error {
	f, err := shared.OpenFile(path)
	if err != nil {
		return err
	}
	defer f.Close()
	fileType := magic.Detect(f)
	if _, err := f.Seek(0, 0); err != nil {
		return err
	}
	switch fileType {
	case magic.FileTypeRPM:
		return verifyRpm(f)
	case magic.FileTypeDEB:
		return verifyDeb(f)
	case magic.FileTypePGP:
		return verifyPgp(f)
	case magic.FileTypeJAR:
		return verifyJar(f)
	case magic.FileTypePKCS7:
		return verifyPkcs(f)
	case magic.FileTypePECOFF:
		return verifyPeCoff(f)
	case magic.FileTypeMSI:
		return verifyMsi(f)
	case magic.FileTypeCAB:
		return verifyCab(f)
	}
	if style, ok := authenticode.GetSigStyle(path); ok {
		return verifyPowershell(f, style)
	}
	return errors.New("unknown filetype")
}

func loadCerts() error {
	trusted, err := certloader.LoadAnyCerts(argTrustedCerts)
	if err != nil {
		return err
	}
	trustedCerts = trusted.X509Certs
	trustedPgp = trusted.PGPCerts
	if len(trustedCerts) > 0 {
		if argAlsoSystem {
			var err error
			trustedPool, err = x509.SystemCertPool()
			if err != nil {
				return err
			}
		} else {
			trustedPool = x509.NewCertPool()
		}
		for _, cert := range trustedCerts {
			trustedPool.AddCert(cert)
		}
	}
	intermediate, err := certloader.LoadAnyCerts(argIntermediateCerts)
	if err != nil {
		return err
	}
	intermediateCerts = intermediate.X509Certs
	return nil
}
