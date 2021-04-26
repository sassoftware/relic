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
	"bytes"
	"crypto"
	"crypto/hmac"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"

	"github.com/sassoftware/relic/lib/pkcs7"
	"github.com/sassoftware/relic/lib/pkcs9"
	"github.com/sassoftware/relic/lib/x509tools"
	"github.com/sassoftware/relic/signers/sigerrors"
)

type PESignature struct {
	pkcs9.TimestampedSignature
	Indirect      *SpcIndirectDataContentPe
	ImageHashFunc crypto.Hash
	PageHashes    []byte
	PageHashFunc  crypto.Hash
}

// Extract and verify the signature from a PE/COFF image file. Does not check X509 chains.
func VerifyPE(r io.ReadSeeker, skipDigests bool) ([]PESignature, error) {
	hvals, err := findSignatures(r)
	if err != nil {
		return nil, err
	} else if hvals.certSize == 0 {
		return nil, sigerrors.NotSignedError{Type: "PECOFF"}
	}
	// Read certificate table
	sigblob := make([]byte, hvals.certSize)
	r.Seek(hvals.certStart, 0)
	if _, err := io.ReadFull(r, sigblob); err != nil {
		return nil, err
	}
	// Parse and verify signatures
	if skipDigests {
		r = nil
	}
	return checkSignatures(sigblob, r)
}

func findSignatures(r io.ReadSeeker) (*peHeaderValues, error) {
	if _, err := r.Seek(0, 0); err != nil {
		return nil, err
	}
	d := ioutil.Discard
	peStart, err := readDosHeader(r, d)
	if err != nil {
		return nil, err
	}
	r.Seek(peStart, 0)
	fh, err := readCoffHeader(r, d)
	if err != nil {
		return nil, err
	}
	return readOptHeader(r, d, peStart, fh)
}

func checkSignatures(blob []byte, image io.ReadSeeker) ([]PESignature, error) {
	values := make(map[crypto.Hash][]byte)
	phvalues := make(map[crypto.Hash][]byte)
	allhashes := make(map[crypto.Hash]bool)
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
		allhashes[sig.ImageHashFunc] = true
		if len(sig.PageHashes) > 0 {
			phvalues[sig.PageHashFunc] = sig.PageHashes
			allhashes[sig.PageHashFunc] = true
		}
		sigs = append(sigs, *sig)
		imageDigest := sig.Indirect.MessageDigest.Digest
		if existing := values[sig.ImageHashFunc]; existing == nil {
			values[sig.ImageHashFunc] = imageDigest
		} else if !hmac.Equal(imageDigest, existing) {
			// they can't both be right...
			return nil, fmt.Errorf("digest mismatch: %x != %x", imageDigest, existing)
		}
	}
	if image == nil {
		return sigs, nil
	}
	for hash := range allhashes {
		imagehash := values[hash]
		pagehashes := phvalues[hash]
		if _, err := image.Seek(0, 0); err != nil {
			return nil, err
		}
		doPageHashes := len(pagehashes) > 0
		digest, err := DigestPE(image, hash, doPageHashes)
		if err != nil {
			return nil, err
		}
		if imagehash != nil && !hmac.Equal(digest.Imprint, imagehash) {
			return nil, fmt.Errorf("digest mismatch: %x != %x", digest.Imprint, imagehash)
		}
		if pagehashes != nil && !hmac.Equal(digest.PageHashes, pagehashes) {
			return nil, fmt.Errorf("page hash mismatch")
		}
	}
	return sigs, nil
}

func checkSignature(der []byte) (*PESignature, error) {
	psd, err := pkcs7.Unmarshal(der)
	if err != nil {
		return nil, fmt.Errorf("unmarshaling authenticode signature: %w", err)
	}
	if !psd.Content.ContentInfo.ContentType.Equal(OidSpcIndirectDataContent) {
		return nil, errors.New("not an authenticode signature")
	}
	sig, err := psd.Content.Verify(nil, false)
	if err != nil {
		return nil, fmt.Errorf("verifying indirect signature: %w", err)
	}
	ts, err := pkcs9.VerifyOptionalTimestamp(sig)
	if err != nil {
		return nil, fmt.Errorf("verifying timestamp: %w", err)
	}
	indirect := new(SpcIndirectDataContentPe)
	if err := psd.Content.ContentInfo.Unmarshal(indirect); err != nil {
		return nil, fmt.Errorf("unmarshaling SpcIndirectDataContentPe: %w", err)
	}
	hash, err := x509tools.PkixDigestToHashE(indirect.MessageDigest.DigestAlgorithm)
	if err != nil {
		return nil, err
	}
	pesig := &PESignature{
		TimestampedSignature: ts,
		Indirect:             indirect,
		ImageHashFunc:        hash,
	}
	if err := readPageHashes(pesig); err != nil {
		return nil, err
	}
	return pesig, nil
}

func readPageHashes(sig *PESignature) error {
	serObj := sig.Indirect.Data.Value.File.Moniker
	if !bytes.Equal(serObj.ClassID, SpcUUIDPageHashes) {
		// not present
		return nil
	}
	// unnecessary SET wrapped around the solitary attribute SEQ
	var attrRaw asn1.RawValue
	if _, err := asn1.Unmarshal(serObj.SerializedData, &attrRaw); err != nil {
		return fmt.Errorf("unmarshaling page hashes: %w", err)
	}
	var attr SpcAttributePageHashes
	if _, err := asn1.Unmarshal(attrRaw.Bytes, &attr); err != nil {
		return fmt.Errorf("unmarshaling SpcAttributePageHashes: %w", err)
	}
	switch {
	case attr.Type.Equal(OidSpcPageHashV1):
		sig.PageHashFunc = crypto.SHA1
	case attr.Type.Equal(OidSpcPageHashV2):
		sig.PageHashFunc = crypto.SHA256
	default:
		return errors.New("unknown page hash format")
	}
	// unnecessary SET wrapped around the octets too
	sig.PageHashes = attr.Hashes[0]
	if len(sig.PageHashes) == 0 || len(sig.PageHashes)%(4+sig.PageHashFunc.Size()) != 0 {
		return errors.New("malformed page hash")
	}
	return nil
}
