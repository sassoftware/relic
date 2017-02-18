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
	"crypto"
	"errors"
	"io"
	"io/ioutil"
	"os"

	"gerrit-pdt.unx.sas.com/tools/relic.git/cmdline/shared"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/atomicfile"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/authenticode"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/comdoc"
	"github.com/spf13/cobra"
)

var SignMsiCmd = &cobra.Command{
	Use:   "sign-msi",
	Short: "Sign a PE-COFF executable using a token",
	RunE:  signMsiCmd,
}

var argNoMsiExtended bool

func init() {
	shared.RootCmd.AddCommand(SignMsiCmd)
	shared.AddDigestFlag(SignMsiCmd)
	SignMsiCmd.Flags().StringVarP(&argKeyName, "key", "k", "", "Name of key section in config file to use")
	SignMsiCmd.Flags().StringVarP(&argFile, "file", "f", "", "Input file to sign")
	SignMsiCmd.Flags().StringVarP(&argOutput, "output", "o", "", "Output file. Defaults to same as input.")
	SignMsiCmd.Flags().BoolVar(&argNoMsiExtended, "no-extended-sig", false, "Don't emit a MsiDigitalSignatureEx digest")
	SignMsiCmd.Flags().BoolVar(&argPkcs7, "pkcs7", false, "Emit PKCS7 signature instead of the signed executable")
}

func signMsiCmd(cmd *cobra.Command, args []string) error {
	if argFile == "" {
		return errors.New("--key and --file are required")
	} else if !argPkcs7 && (argFile == "-" || argOutput == "-") {
		return errors.New("--file and --output must be a path, not -")
	}
	hash, err := shared.GetDigest()
	if err != nil {
		return err
	}
	sum, exsig, err := signMsiInput(hash)
	if err != nil {
		return shared.Fail(err)
	}

	key, err := openKey(argKeyName)
	if err != nil {
		return err
	}
	certs, err := readCerts(key)
	if err != nil {
		return shared.Fail(err)
	}
	psd, err := authenticode.SignMSIImprint(sum, hash, key, certs)
	if err != nil {
		return shared.Fail(err)
	}
	pkcs, err := timestampPkcs(psd, key, certs, hash, true)
	if err != nil {
		return shared.Fail(err)
	}
	if argPkcs7 {
		if argOutput == "" {
			argOutput = "-"
		}
		return shared.Fail(atomicfile.WriteFile(argOutput, pkcs))
	} else {
		if argOutput == "" {
			argOutput = argFile
		}
		return writeMsi(pkcs, exsig)
	}
}

func signMsiInput(hash crypto.Hash) (sum, exsig []byte, err error) {
	if argPkcs7 && argFile == "-" {
		// the input is actually the imprint digest
		sum, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			return nil, nil, err
		}
		return sum, nil, nil
	} else {
		cdf, err := comdoc.ReadPath(argFile)
		if err != nil {
			return nil, nil, shared.Fail(err)
		}
		defer cdf.Close()
		return authenticode.DigestMSI(cdf, hash, !argNoMsiExtended)
	}
}

func writeMsi(pkcs, exsig []byte) error {
	if argFile != argOutput {
		// make a copy
		outfile, err := os.Create(argOutput)
		if err != nil {
			return shared.Fail(err)
		}
		infile, err := os.Open(argFile)
		if err != nil {
			return shared.Fail(err)
		}
		if _, err := io.Copy(outfile, infile); err != nil {
			return shared.Fail(err)
		}
		infile.Close()
		outfile.Close()
	}
	cdf, err := comdoc.WritePath(argOutput)
	if err != nil {
		return shared.Fail(err)
	}
	if err := authenticode.InsertMSISignature(cdf, pkcs, exsig); err != nil {
		return shared.Fail(err)
	}
	if err := cdf.Close(); err != nil {
		return shared.Fail(err)
	}
	return nil
}
