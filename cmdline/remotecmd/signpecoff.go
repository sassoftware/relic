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
	"crypto"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/url"
	"os"
	"path"

	"gerrit-pdt.unx.sas.com/tools/relic.git/cmdline/shared"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/atomicfile"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/authenticode"
)

func signPeCoff() error {
	if argFile == "-" || argOutput == "-" {
		return errors.New("--file and --output must be paths, not -")
	}
	infile, err := os.Open(argFile)
	if err != nil {
		return shared.Fail(err)
	}
	defer infile.Close()

	values := url.Values{}
	values.Add("sigtype", "pe-coff")
	values.Add("key", argKeyName)
	values.Add("filename", path.Base(argFile))
	if err := setDigestQueryParam(values); err != nil {
		return err
	}
	if argPageHashes {
		digest, _ := shared.GetDigest()
		if digest != crypto.SHA256 && digest != crypto.SHA1 {
			return errors.New("when --page-hashes is set, SHA1 or SHA256 must be used")
		}
		values.Add("page-hashes", "1")
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
	fmt.Fprintf(os.Stderr, "Signed %s\n", argFile)
	return nil
}
