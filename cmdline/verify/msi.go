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
	"encoding/asn1"
	"errors"
	"io/ioutil"
	"os"

	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/comdoc"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/pkcs7"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/pkcs9"
)

const msiSigName = "\x05DigitalSignature"

func verifyMsi(f *os.File) error {
	if !argNoIntegrityCheck {
		return errors.New("msi integrity check not supported yet, use --no-integrity-check")
	}
	cdf, err := comdoc.NewReader(f)
	if err != nil {
		return err
	}
	var der []byte
	for _, info := range cdf.Files {
		if info.Name() == msiSigName {
			r, err := cdf.ReadStream(info)
			if err != nil {
				return err
			}
			der, err = ioutil.ReadAll(r)
			if err != nil {
				return err
			}
			break
		}
	}
	if len(der) == 0 {
		return errors.New("MSI is not signed")
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
