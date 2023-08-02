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
	"context"
	"crypto"
	"encoding/asn1"
	"errors"

	"github.com/sassoftware/relic/v7/lib/certloader"
	"github.com/sassoftware/relic/v7/lib/pkcs7"
	"github.com/sassoftware/relic/v7/lib/pkcs9"
	"github.com/sassoftware/relic/v7/lib/x509tools"
)

type OpusParams struct {
	Description string
	URL         string
}

func makePeIndirect(imprint []byte, hash crypto.Hash, oid asn1.ObjectIdentifier) (indirect SpcIndirectDataContentPe, err error) {
	alg, ok := x509tools.PkixDigestAlgorithm(hash)
	if !ok {
		err = errors.New("unsupported digest algorithm")
		return
	}
	indirect.Data.Type = oid
	indirect.MessageDigest.Digest = imprint
	indirect.MessageDigest.DigestAlgorithm = alg
	indirect.Data.Value.File.File = NewSpcString("")
	return
}

func signIndirect(ctx context.Context, indirect interface{}, hash crypto.Hash, cert *certloader.Certificate, params *OpusParams) (*pkcs9.TimestampedSignature, error) {
	sig := pkcs7.NewBuilder(cert.Signer(), cert.Chain(), hash)
	if err := sig.SetContent(OidSpcIndirectDataContent, indirect); err != nil {
		return nil, err
	}
	if err := addOpusAttrs(sig, params); err != nil {
		return nil, err
	}
	psd, err := sig.Sign()
	if err != nil {
		return nil, err
	}
	return pkcs9.TimestampAndMarshal(ctx, psd, cert.Timestamper, true)
}

func addOpusAttrs(sig *pkcs7.SignatureBuilder, params *OpusParams) error {
	if err := sig.AddAuthenticatedAttribute(OidSpcStatementType, SpcSpStatementType{Type: OidSpcIndividualPurpose}); err != nil {
		return err
	}
	var info SpcSpOpusInfo
	if params != nil {
		if params.Description != "" {
			info.ProgramName = NewSpcString(params.Description)
		}
		if params.URL != "" {
			info.MoreInfo.URL = params.URL
		}
	}
	if err := sig.AddAuthenticatedAttribute(OidSpcSpOpusInfo, info); err != nil {
		return err
	}
	return nil
}

func SignSip(ctx context.Context, imprint []byte, hash crypto.Hash, sipInfo SpcSipInfo, cert *certloader.Certificate, params *OpusParams) (*pkcs9.TimestampedSignature, error) {
	alg, ok := x509tools.PkixDigestAlgorithm(hash)
	if !ok {
		return nil, errors.New("unsupported digest algorithm")
	}
	var indirect SpcIndirectDataContentMsi
	indirect.Data.Type = OidSpcSipInfo
	indirect.Data.Value = sipInfo
	indirect.MessageDigest.Digest = imprint
	indirect.MessageDigest.DigestAlgorithm = alg
	return signIndirect(ctx, indirect, hash, cert, params)
}
