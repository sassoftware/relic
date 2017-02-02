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
	"fmt"
	"io/ioutil"
	"os"

	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/pkcs7"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/pkcs9"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/x509tools"
)

func verifyPkcs(f *os.File) error {
	der, err := ioutil.ReadAll(f)
	if err != nil {
		return err
	}
	var psd pkcs7.ContentInfoSignedData
	if _, err := asn1.Unmarshal(der, &psd); err != nil {
		return err
	}
	var content []byte
	if argContent != "" {
		content, err = ioutil.ReadFile(argContent)
		if err != nil {
			return err
		}
	}
	sig, err := psd.Content.Verify(content, argNoIntegrityCheck)
	if err != nil {
		return err
	}
	ts, err := pkcs9.VerifyOptionalTimestamp(sig)
	if err != nil {
		return err
	}
	return doPkcs(f.Name(), ts, x509.ExtKeyUsageAny)
}

func doPkcs(name string, ts pkcs9.TimestampedSignature, usage x509.ExtKeyUsage) error {
	if !argNoChain {
		if err := ts.VerifyChain(trustedPool, intermediateCerts, usage); err != nil {
			fmt.Printf("%s(timestamp): UNTRUSTED - %s\n", name, x509tools.FormatRDNSequence(ts.Certificate.Subject.ToRDNSequence()))
			return err
		}
	}
	if ts.CounterSignature == nil {
		fmt.Printf("%s(timestamp): not present\n", name)
	} else {
		fmt.Printf("%s(timestamp): OK - [%s] %s\n", name, ts.CounterSignature.SigningTime, x509tools.FormatRDNSequence(ts.CounterSignature.Certificate.Subject.ToRDNSequence()))
	}
	fmt.Printf("%s: OK - %s\n", name, x509tools.FormatRDNSequence(ts.Signature.Certificate.Subject.ToRDNSequence()))
	return nil
}
