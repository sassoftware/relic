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
	"crypto/hmac"
	"errors"
	"fmt"
	"io"

	"github.com/sassoftware/relic/v7/lib/binpatch"
	"github.com/sassoftware/relic/v7/lib/cabfile"
	"github.com/sassoftware/relic/v7/lib/certloader"
	"github.com/sassoftware/relic/v7/lib/pkcs7"
	"github.com/sassoftware/relic/v7/lib/pkcs9"
	"github.com/sassoftware/relic/v7/lib/x509tools"
	"github.com/sassoftware/relic/v7/signers/sigerrors"
)

type CabSignature struct {
	pkcs9.TimestampedSignature
	Indirect *SpcIndirectDataContentPe
	OpusInfo *SpcSpOpusInfo
	HashFunc crypto.Hash
	PatchSet *binpatch.PatchSet
}

// Extract and verify the signature of a CAB file. Does not check X509 chains.
func VerifyCab(f io.ReaderAt, skipDigests bool) (*CabSignature, error) {
	cab, err := cabfile.Parse(io.NewSectionReader(f, 0, 1<<63-1))
	if err != nil {
		return nil, err
	}
	if len(cab.Signature) == 0 {
		return nil, sigerrors.NotSignedError{Type: "cabinet"}
	}
	psd, err := pkcs7.Unmarshal(cab.Signature)
	if err != nil {
		return nil, err
	}
	if !psd.Content.ContentInfo.ContentType.Equal(OidSpcIndirectDataContent) {
		return nil, errors.New("not an authenticode signature")
	}
	pksig, err := psd.Content.Verify(nil, false)
	if err != nil {
		return nil, err
	}
	ts, err := pkcs9.VerifyOptionalTimestamp(pksig)
	if err != nil {
		return nil, err
	}
	indirect := new(SpcIndirectDataContentPe)
	if err := psd.Content.ContentInfo.Unmarshal(indirect); err != nil {
		return nil, err
	}
	hash, err := x509tools.PkixDigestToHashE(indirect.MessageDigest.DigestAlgorithm)
	if err != nil {
		return nil, err
	}
	opus, err := GetOpusInfo(pksig.SignerInfo)
	if err != nil {
		return nil, err
	}
	cabsig := &CabSignature{
		TimestampedSignature: ts,
		Indirect:             indirect,
		HashFunc:             hash,
		OpusInfo:             opus,
	}
	if !skipDigests {
		digest, err := cabfile.Digest(io.NewSectionReader(f, 0, 1<<63-1), hash)
		if err != nil {
			return nil, err
		}
		if !hmac.Equal(digest.Imprint, indirect.MessageDigest.Digest) {
			return nil, fmt.Errorf("digest mismatch: %x != %x", digest.Imprint, indirect.MessageDigest.Digest)
		}
		// cab signatures seem to come with a "page hash" link in the same way
		// as PE files can, using OidSpcCabPageHash as the type, but it's not
		// clear what it's hashing.
	}
	return cabsig, nil
}

// Create the Authenticode structure for a CAB file signature using a previously-calculated digest (imprint).
func SignCabImprint(ctx context.Context, digest *cabfile.CabinetDigest, cert *certloader.Certificate, params *OpusParams) (*binpatch.PatchSet, *pkcs9.TimestampedSignature, error) {
	indirect, err := makePeIndirect(digest.Imprint, digest.HashFunc, OidSpcCabImageData)
	if err != nil {
		return nil, nil, err
	}
	ts, err := signIndirect(ctx, indirect, digest.HashFunc, cert, params)
	if err != nil {
		return nil, nil, err
	}
	patch := digest.MakePatch(ts.Raw)
	return patch, ts, nil
}
