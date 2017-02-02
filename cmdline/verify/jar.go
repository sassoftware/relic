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
	"io"
	"os"

	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/signjar"
)

func verifyJar(f *os.File) error {
	size, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		return err
	}
	f.Seek(0, 0)
	sigs, err := signjar.Verify(f, size, argNoIntegrityCheck)
	if err != nil {
		return err
	}
	var lasterr error
	for _, sig := range sigs {
		if err := doPkcs(f.Name(), *sig, x509.ExtKeyUsageCodeSigning); err != nil {
			lasterr = err
		}
	}
	return lasterr
}
