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
	"io"
	"os"

	"gerrit-pdt.unx.sas.com/tools/relic.git/cmdline/shared"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/atomicfile"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/authenticode"
	"github.com/spf13/cobra"
)

var SignPeCmd = &cobra.Command{
	Use:   "sign-pe",
	Short: "Sign a PE-COFF executable using a token",
	RunE:  signPeCmd,
}

var (
	argPkcs7      bool
	argPageHashes bool
)

func init() {
	shared.RootCmd.AddCommand(SignPeCmd)
	shared.AddDigestFlag(SignPeCmd)
	SignPeCmd.Flags().StringVarP(&argKeyName, "key", "k", "", "Name of key section in config file to use")
	SignPeCmd.Flags().StringVarP(&argFile, "file", "f", "", "Input file to sign")
	SignPeCmd.Flags().StringVarP(&argOutput, "output", "o", "", "Output file. Defaults to same as input.")
	SignPeCmd.Flags().BoolVar(&argPkcs7, "pkcs7", false, "Emit PKCS7 signature instead of the signed executable")
	SignPeCmd.Flags().BoolVar(&argPageHashes, "page-hashes", false, "Add page hashes to signature")
}

func signPeCmd(cmd *cobra.Command, args []string) (err error) {
	if argFile == "" {
		return errors.New("--key and --file are required")
	} else if !argPkcs7 && (argFile == "-" || argOutput == "-") {
		return errors.New("--file and --output must be paths, not -")
	}
	var infile *os.File
	if argFile == "-" {
		infile = os.Stdin
	} else {
		infile, err = os.Open(argFile)
		if err != nil {
			return err
		}
		defer infile.Close()
	}
	pkcs, err := signPeInput(infile)
	if err != nil {
		return err
	}
	if argPkcs7 {
		if argOutput == "" {
			argOutput = "-"
		}
		err = atomicfile.WriteFile(argOutput, pkcs)
		return shared.Fail(err)
	} else {
		if argOutput == "" {
			argOutput = argFile
		}
		return writePe(infile, pkcs)
	}
}

func signPeInput(r io.Reader) ([]byte, error) {
	hash, err := shared.GetDigest()
	if err != nil {
		return nil, err
	}
	key, err := openKey(argKeyName)
	if err != nil {
		return nil, err
	}
	certs, err := readCerts(key)
	if err != nil {
		return nil, shared.Fail(err)
	}
	sum, pagehashes, err := authenticode.DigestPE(r, hash, argPageHashes)
	if err != nil {
		return nil, shared.Fail(err)
	}
	psd, err := authenticode.SignImprint(sum, hash, pagehashes, hash, key, certs)
	if err != nil {
		return nil, shared.Fail(err)
	}
	pkcs, err := timestampPkcs(psd, key, certs, hash)
	if err != nil {
		return nil, shared.Fail(err)
	}
	return pkcs, nil
}

func writePe(infile *os.File, pkcs []byte) error {
	outfile, err := atomicfile.New(argOutput)
	if err != nil {
		return shared.Fail(err)
	}
	defer outfile.Close()
	if _, err := infile.Seek(0, 0); err != nil {
		return shared.Fail(err)
	}
	if _, err := io.Copy(outfile, infile); err != nil {
		return shared.Fail(err)
	}
	if err := authenticode.InsertPESignature(outfile, pkcs); err != nil {
		return shared.Fail(err)
	}
	infile.Close()
	if err := outfile.Commit(); err != nil {
		return shared.Fail(err)
	}
	return nil
}
