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

package pkcs9

import (
	"crypto/hmac"
	"errors"

	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/x509tools"
)

func (i MessageImprint) Verify(data []byte) error {
	hash, ok := x509tools.PkixDigestToHash(i.HashAlgorithm)
	if !ok || !hash.Available() {
		return errors.New("pkcs9: unknown digest algorithm")
	}
	w := hash.New()
	w.Write(data)
	digest := w.Sum(nil)
	if !hmac.Equal(digest, i.HashedMessage) {
		return errors.New("pkcs9: digest check failed")
	}
	return nil
}
