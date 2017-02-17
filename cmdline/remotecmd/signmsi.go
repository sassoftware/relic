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

package remotecmd

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/url"
	"os"
	"path"

	"gerrit-pdt.unx.sas.com/tools/relic.git/cmdline/shared"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/authenticode"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/comdoc"
)

func signMsi() error {
	if argFile == "-" || argOutput == "-" {
		return errors.New("--file and --output must be paths, not -")
	}
	hash, err := shared.GetDigest()
	if err != nil {
		return err
	}
	sum, exsig, err := signMsiInput(hash)
	if err != nil {
		return shared.Fail(err)
	}
	infile := bytes.NewReader(sum)

	values := url.Values{}
	values.Add("sigtype", "msi-imprint")
	values.Add("key", argKeyName)
	values.Add("filename", path.Base(argFile))
	if err := setDigestQueryParam(values); err != nil {
		return err
	}
	response, err := CallRemote("sign", "POST", &values, infile)
	if err != nil {
		return shared.Fail(err)
	}
	defer response.Body.Close()
	pkcs, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return shared.Fail(err)
	}

	if argOutput == "" {
		argOutput = argFile
	}
	if err := writeMsi(pkcs, exsig); err != nil {
		return shared.Fail(err)
	}
	fmt.Fprintf(os.Stderr, "Signed %s\n", argFile)
	return nil
}

func signMsiInput(hash crypto.Hash) (sum, exsig []byte, err error) {
	cdf, err := comdoc.ReadPath(argFile)
	if err != nil {
		return nil, nil, err
	}
	defer cdf.Close()
	return authenticode.DigestMSI(cdf, hash, !argNoMsiExtended)
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
	fmt.Printf("%x\n", exsig)
	if err := authenticode.InsertMSISignature(cdf, pkcs, exsig); err != nil {
		return shared.Fail(err)
	}
	if err := cdf.Close(); err != nil {
		return shared.Fail(err)
	}
	return nil
}
