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

package authenticode

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"

	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/pkcs7"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/pkcs9"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/x509tools"
)

type PESignature struct {
	pkcs9.TimestampedSignature
	Indirect  SpcIndirectDataContent
	ImageHash crypto.Hash
}

func VerifyPE(r io.ReadSeeker, skipDigests bool) ([]PESignature, error) {
	_, certStart, certSize, err := findSignatures(r)
	if err != nil {
		return nil, err
	} else if certSize == 0 {
		return nil, errors.New("image does not contain any signatures")
	}
	// Read certificate table
	sigblob := make([]byte, certSize)
	r.Seek(certStart, 0)
	if _, err := io.ReadFull(r, sigblob); err != nil {
		return nil, err
	}
	// Parse and verify signatures
	if skipDigests {
		r = nil
	} else {
		r.Seek(0, 0)
	}
	return checkSignatures(sigblob, r)
}

func findSignatures(r io.ReadSeeker) (posDDCert, certStart, certSize int64, err error) {
	if _, err := r.Seek(0, 0); err != nil {
		return 0, 0, 0, err
	}
	d := ioutil.Discard
	peStart, err := readDosHeader(r, d)
	if err != nil {
		return 0, 0, 0, err
	}
	r.Seek(peStart, 0)
	fh, err := readCoffHeader(r, d)
	if err != nil {
		return 0, 0, 0, err
	}
	posDDCert, _, _, certStart, certSize, err = readOptHeader(r, d, peStart, fh)
	return
}

func checkSignatures(blob []byte, image io.Reader) ([]PESignature, error) {
	values := make(map[crypto.Hash][]byte, 1)
	sigs := make([]PESignature, 0, 1)
	for len(blob) != 0 {
		wLen := binary.LittleEndian.Uint32(blob[:4])
		end := (int(wLen) + 7) / 8 * 8
		size := int(wLen) - 8
		if end > len(blob) || size < 0 {
			return nil, errors.New("invalid certificate table")
		}
		cert := blob[8 : 8+size]
		blob = blob[end:]

		sig, err := checkSignature(cert)
		if err != nil {
			return nil, err
		}
		sigs = append(sigs, *sig)
		if image == nil {
			continue
		}
		imageDigest := sig.Indirect.MessageDigest.Digest
		if existing := values[sig.ImageHash]; existing == nil {
			values[sig.ImageHash] = imageDigest
		} else if !hmac.Equal(imageDigest, existing) {
			// they can't both be right...
			return nil, fmt.Errorf("digest mismatch: %x != %x", imageDigest, existing)
		}
	}
	if image != nil {
		hashes := make([]crypto.Hash, 0, len(values))
		for hash := range values {
			hashes = append(hashes, hash)
		}
		sums, err := DigestPE(image, hashes)
		if err != nil {
			return nil, err
		}
		for i, hash := range hashes {
			value := values[hash]
			calc := sums[i]
			if !hmac.Equal(calc, value) {
				return nil, fmt.Errorf("digest mismatch: %x != %x", calc, value)
			}
		}
	}
	return sigs, nil
}

func checkSignature(der []byte) (*PESignature, error) {
	var psd pkcs7.ContentInfoSignedData
	if rest, err := asn1.Unmarshal(der, &psd); err != nil {
		return nil, err
	} else if len(bytes.TrimRight(rest, "\x00")) != 0 {
		return nil, errors.New("trailing garbage after signature")
	}
	if !psd.Content.ContentInfo.ContentType.Equal(OidSpcIndirectDataContent) {
		return nil, errors.New("not an authenticode signature")
	}
	sig, err := psd.Content.Verify(nil, false)
	if err != nil {
		return nil, err
	}
	ts, err := pkcs9.VerifyOptionalTimestamp(sig)
	if err != nil {
		return nil, err
	}
	var indirect SpcIndirectDataContent
	if err := psd.Content.ContentInfo.Unmarshal(&indirect); err != nil {
		return nil, err
	}
	hash, ok := x509tools.PkixDigestToHash(indirect.MessageDigest.DigestAlgorithm)
	if !ok || !hash.Available() {
		return nil, fmt.Errorf("unsupported hash algorithm %s", indirect.MessageDigest.DigestAlgorithm.Algorithm)
	}
	return &PESignature{
		TimestampedSignature: ts,
		Indirect:             indirect,
		ImageHash:            hash,
	}, nil
}
