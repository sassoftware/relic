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

package pkcs7

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
)

func ParseCertificates(der []byte) ([]*x509.Certificate, error) {
	var psd ContentInfoSignedData
	_, err := asn1.Unmarshal(der, &psd)
	if err != nil {
		return nil, fmt.Errorf("pkcs7: %s", err)
	}
	blob := psd.Content.Certificates.Raw
	if len(blob) == 0 {
		return nil, errors.New("pkcs7: no certificates")
	}
	var val asn1.RawValue
	if _, err := asn1.Unmarshal(blob, &val); err != nil {
		return nil, err
	}
	return x509.ParseCertificates(val.Bytes)
}

func ExtractAndDetach(der []byte) (pkcs, content []byte, err error) {
	var psd ContentInfoSignedData
	_, err = asn1.Unmarshal(der, &psd)
	if err != nil {
		return nil, nil, fmt.Errorf("pkcs7: %s", err)
	}
	if err := psd.Content.ContentInfo.Unmarshal(&content); err != nil {
		return nil, nil, fmt.Errorf("pkcs7: %s", err)
	}
	psd.Content.ContentInfo, _ = NewContentInfo(psd.Content.ContentInfo.ContentType, nil)
	pkcs, err = asn1.Marshal(psd)
	return pkcs, content, err
}
