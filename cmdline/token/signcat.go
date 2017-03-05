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
	"encoding/asn1"
	"errors"
	"fmt"
	"os"

	"gerrit-pdt.unx.sas.com/tools/relic.git/cmdline/shared"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/atomicfile"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/authenticode"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/pkcs7"
	"github.com/spf13/cobra"
)

var SignCatCmd = &cobra.Command{
	Use:   "sign-cat",
	Short: "Sign a Windows Security Catalog file using a token",
	RunE:  signCatCmd,
}

func init() {
	shared.RootCmd.AddCommand(SignCatCmd)
	shared.AddDigestFlag(SignCatCmd)
	SignCatCmd.Flags().StringVarP(&argKeyName, "key", "k", "", "Name of key section in config file to use")
	SignCatCmd.Flags().StringVarP(&argFile, "file", "f", "", "Input file to sign")
	SignCatCmd.Flags().StringVarP(&argOutput, "output", "o", "", "Output file. Defaults to same as input.")
}

func signCatCmd(cmd *cobra.Command, args []string) (err error) {
	if argFile == "" {
		return errors.New("--key and --file are required")
	}
	blob, err := shared.ReadFile(argFile)
	if err != nil {
		return err
	}
	key, err := openKey(argKeyName)
	if err != nil {
		return err
	}
	certs, err := readCerts(key)
	if err != nil {
		return shared.Fail(err)
	}
	hash, err := shared.GetDigest()
	if err != nil {
		return err
	}

	var oldpsd pkcs7.ContentInfoSignedData
	if _, err := asn1.Unmarshal(blob, &oldpsd); err != nil {
		return shared.Fail(err)
	}
	if !oldpsd.Content.ContentInfo.ContentType.Equal(authenticode.OidCertTrustList) {
		return shared.Fail(errors.New("not a security catalog"))
	}
	sig := pkcs7.NewBuilder(key, certs, hash)
	if err := sig.SetContentInfo(oldpsd.Content.ContentInfo); err != nil {
		return shared.Fail(err)
	}
	newpsd, err := sig.Sign()
	if err != nil {
		return shared.Fail(err)
	}
	sigblob, err := timestampPkcs(newpsd, key, certs, hash, true)
	if err != nil {
		return shared.Fail(err)
	}

	if argOutput == "" {
		argOutput = argFile
	}
	if err := atomicfile.WriteFile(argOutput, sigblob); err != nil {
		return shared.Fail(err)
	}
	fmt.Fprintf(os.Stderr, "Signed %s\n", argFile)
	attrs := NewAudit(key, "cat", hash)
	attrs.SetX509Cert(certs[0])
	return PublishAudit(attrs)
}
