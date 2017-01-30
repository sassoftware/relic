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
	"crypto/x509/pkix"
	"encoding/asn1"
)

func (g GeneralName) RDNSequence() pkix.RDNSequence {
	if g.Value.Tag != 4 {
		return nil
	}
	var seq pkix.RDNSequence
	if _, err := asn1.Unmarshal(g.Value.Bytes, &seq); err != nil {
		return nil
	}
	return seq
}
