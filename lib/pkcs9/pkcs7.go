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
	"errors"

	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/pkcs7"
)

func AddStampToSignedData(signerInfo *pkcs7.SignerInfo, token pkcs7.ContentInfoSignedData) error {
	return signerInfo.UnauthenticatedAttributes.Add(OidAttributeTimeStampToken, token)
}

func VerifyCounterSignature(psd *pkcs7.ContentInfoSignedData) error {
	if len(psd.Content.SignerInfos) != 1 {
		return errors.New("expected exactly one SignerInfo")
	}
	si := psd.Content.SignerInfos[0]
	var tst pkcs7.ContentInfoSignedData
	var tsi pkcs7.SignerInfo
	certs, err := psd.Content.Certificates.Parse()
	if err != nil {
		return err
	}
	// check several OIDs for timestamp tokens
	err = si.UnauthenticatedAttributes.GetOne(OidAttributeTimeStampToken, &tst)
	if _, ok := err.(pkcs7.ErrNoAttribute); ok {
		err = si.UnauthenticatedAttributes.GetOne(OidSpcTimeStampToken, &tst)
	}
	if err == nil {
		// timestamptoken is a fully nested signedData
		if len(tst.Content.SignerInfos) != 1 {
			return errors.New("counter-signature should have exactly one SignerInfo")
		}
		tsi = tst.Content.SignerInfos[0]
		tsicerts, err := tst.Content.Certificates.Parse()
		if err != nil {
			return err
		} else if len(tsicerts) != 0 {
			// keep both sets of certs just in case
			certs = append(certs, tsicerts...)
		}
	} else if _, ok := err.(pkcs7.ErrNoAttribute); ok {
		if err := si.UnauthenticatedAttributes.GetOne(OidAttributeCounterSign, &tsi); err != nil {
			return err
		}
		// counterSignature is just a signerinfo and the certificates come from
		// the parent signedData
	} else {
		return err
	}
	return tsi.Verify(si.EncryptedDigest, certs)
}
