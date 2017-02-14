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
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"strings"

	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/pkcs7"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/pkcs9"
)

func verifyMsi(f *os.File) error {
	if !argNoIntegrityCheck {
		return errors.New("msi integrity check not supported yet, use --no-integrity-check")
	}
	scratchDir, err := ioutil.TempDir("", "relic-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(scratchDir)
	var stderr bytes.Buffer
	proc := exec.Command("msidump", "-s", "-d", scratchDir, f.Name())
	proc.Stderr = &stderr
	err = proc.Run()
	if err != nil {
		if strings.Contains(err.Error(), "executable file not found") {
			return errors.New("msidump not found, please install msitools")
		}
		return fmt.Errorf("%s\nStandard error:\n%s", err, stderr.String())
	}
	der, err := ioutil.ReadFile(path.Join(scratchDir, "_Streams", "\x05DigitalSignature"))
	if err != nil {
		if os.IsNotExist(err) {
			return errors.New("msi is not signed")
		}
		return err
	}
	var psd pkcs7.ContentInfoSignedData
	if _, err := asn1.Unmarshal(der, &psd); err != nil {
		return err
	}
	sig, err := psd.Content.Verify(nil, false)
	if err != nil {
		return err
	}
	ts, err := pkcs9.VerifyOptionalTimestamp(sig)
	if err != nil {
		return err
	}
	return doPkcs(f.Name(), ts, x509.ExtKeyUsageCodeSigning)
}