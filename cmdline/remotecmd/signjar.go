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
	"archive/zip"
	"bytes"
	"crypto"
	"errors"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"path"

	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/atomicfile"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/pkcs7"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/signjar"
)

func signJar() error {
	inz, err := zip.OpenReader(argFile)
	if err != nil {
		return err
	}
	defer inz.Close()
	hash := crypto.SHA256
	manifest, err := signjar.DigestJar(&inz.Reader, hash)
	if err != nil {
		return err
	}
	infile := bytes.NewReader(manifest)

	values := url.Values{}
	values.Add("sigtype", "jar-manifest")
	values.Add("key", argKeyName)
	values.Add("filename", path.Base(argFile))
	response, err := callRemote("sign", "POST", &values, infile)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	pkcs, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return err
	}

	certs, err := pkcs7.ParseCertificates(pkcs)
	if err != nil {
		return err
	} else if len(certs) == 0 {
		return errors.New("pkcs7: did not contain any certificates")
	}
	pubkey := certs[0].PublicKey
	// The server returns an "opaque" signature with the content, extract the content and remove it from the signature
	pkcs, sigfile, err := pkcs7.ExtractAndDetach(pkcs)
	if err != nil {
		return err
	}
	w, err := atomicfile.WriteAny(argOutput)
	if err != nil {
		return err
	}
	if err := signjar.UpdateJar(w, &inz.Reader, argKeyAlias, pubkey, manifest, sigfile, pkcs); err != nil {
		return err
	}
	inz.Close()
	if err := w.Commit(); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Signed %s\n", argFile)
	return nil
}
