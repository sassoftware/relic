//
// Copyright (c) SAS Institute Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package authenticode

import (
	"crypto"

	"github.com/sassoftware/relic/lib/certloader"
	"github.com/sassoftware/relic/lib/comdoc"
	"github.com/sassoftware/relic/lib/pkcs9"
)

// Create the Authenticode structure for a MSI file signature using a previously-calculated digest (imprint).
func SignMSIImprint(digest []byte, hash crypto.Hash, cert *certloader.Certificate) (*pkcs9.TimestampedSignature, error) {
	return SignSip(digest, hash, msiSipInfo, cert)
}

// Add a signature blob to an open MSI file. The extended signature blob is
// added or updated if provided, or deleted if nil.
func InsertMSISignature(cdf *comdoc.ComDoc, pkcs, exsig []byte) error {
	if len(exsig) > 0 {
		if err := cdf.AddFile(msiDigitalSignatureEx, exsig); err != nil {
			return err
		}
	} else {
		if err := cdf.DeleteFile(msiDigitalSignatureEx); err != nil {
			return err
		}
	}
	return cdf.AddFile(msiDigitalSignature, pkcs)
}
