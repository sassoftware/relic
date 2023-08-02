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

package signxap

import (
	"crypto"
	"crypto/hmac"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/sassoftware/relic/v7/lib/authenticode"
	"github.com/sassoftware/relic/v7/lib/pkcs7"
	"github.com/sassoftware/relic/v7/lib/pkcs9"
	"github.com/sassoftware/relic/v7/lib/x509tools"
	"github.com/sassoftware/relic/v7/signers/sigerrors"
)

type XapSignature struct {
	pkcs9.TimestampedSignature
	Hash     crypto.Hash
	OpusInfo *authenticode.SpcSpOpusInfo
}

func Verify(r io.ReaderAt, size int64, skipDigests bool) (*XapSignature, error) {
	var tr xapTrailer
	if err := binary.Read(io.NewSectionReader(r, size-10, 10), binary.LittleEndian, &tr); err != nil {
		return nil, err
	}
	if tr.Magic != trailerMagic {
		var zipMagic uint32
		if err := binary.Read(io.NewSectionReader(r, size-22, 4), binary.LittleEndian, &zipMagic); err != nil {
			return nil, err
		}
		if zipMagic == 0x06054b50 {
			return nil, sigerrors.NotSignedError{Type: "XAP"}
		}
		return nil, errors.New("invalid xap file")
	}
	size -= int64(tr.TrailerSize) + 10
	var hdr xapHeader
	if err := binary.Read(io.NewSectionReader(r, size, 8), binary.LittleEndian, &hdr); err != nil {
		return nil, err
	}
	if hdr.SignatureSize != tr.TrailerSize-8 {
		return nil, errors.New("invalid xap file")
	}
	blob := make([]byte, hdr.SignatureSize)
	if n, err := r.ReadAt(blob, size+8); err != nil {
		return nil, err
	} else if n < len(blob) {
		return nil, io.ErrUnexpectedEOF
	}
	psd, err := pkcs7.Unmarshal(blob)
	if err != nil {
		return nil, fmt.Errorf("invalid signature: %w", err)
	}
	if !psd.Content.ContentInfo.ContentType.Equal(authenticode.OidSpcIndirectDataContent) {
		return nil, fmt.Errorf("invalid signature: %s", "not an authenticode signature")
	}
	pksig, err := psd.Content.Verify(nil, false)
	if err != nil {
		return nil, fmt.Errorf("invalid signature: %w", err)
	}
	ts, err := pkcs9.VerifyOptionalTimestamp(pksig)
	if err != nil {
		return nil, err
	}
	indirect := new(authenticode.SpcIndirectDataContentMsi)
	if err := psd.Content.ContentInfo.Unmarshal(indirect); err != nil {
		return nil, fmt.Errorf("invalid signature: %w", err)
	}
	hash, err := x509tools.PkixDigestToHashE(indirect.MessageDigest.DigestAlgorithm)
	if err != nil {
		return nil, err
	}
	opus, err := authenticode.GetOpusInfo(pksig.SignerInfo)
	if err != nil {
		return nil, err
	}
	if !skipDigests {
		d := hash.New()
		if _, err := io.Copy(d, io.NewSectionReader(r, 0, size)); err != nil {
			return nil, err
		}
		calc := d.Sum(nil)
		expected := indirect.MessageDigest.Digest
		if !hmac.Equal(calc, expected) {
			return nil, fmt.Errorf("digest mismatch: calculated %x != found %x", calc, expected)
		}
	}
	return &XapSignature{
		TimestampedSignature: ts,
		Hash:                 hash,
		OpusInfo:             opus,
	}, nil
}
