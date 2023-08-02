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
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/sassoftware/relic/v7/lib/comdoc"
	"github.com/sassoftware/relic/v7/lib/pkcs7"
	"github.com/sassoftware/relic/v7/lib/pkcs9"
	"github.com/sassoftware/relic/v7/lib/x509tools"
	"github.com/sassoftware/relic/v7/signers/sigerrors"
)

type MSISignature struct {
	pkcs9.TimestampedSignature
	Indirect *SpcIndirectDataContentMsi
	HashFunc crypto.Hash
	OpusInfo *SpcSpOpusInfo
}

// Extract and verify the signature of a MSI file. Does not check X509 chains.
func VerifyMSI(f io.ReaderAt, skipDigests bool) (*MSISignature, error) {
	cdf, err := comdoc.ReadFile(f)
	if err != nil {
		return nil, err
	}
	var sig, exsig []byte
	files, err := cdf.ListDir(nil)
	if err != nil {
		return nil, err
	}
	for _, item := range files {
		name := item.Name()
		if name == msiDigitalSignature {
			r, err := cdf.ReadStream(item)
			if err == nil {
				sig, err = io.ReadAll(r)
			}
			if err != nil {
				return nil, err
			}
		} else if name == msiDigitalSignatureEx {
			r, err := cdf.ReadStream(item)
			if err == nil {
				exsig, err = io.ReadAll(r)
			}
			if err != nil {
				return nil, err
			}
		}
	}
	if len(sig) == 0 {
		return nil, sigerrors.NotSignedError{Type: "MSI"}
	}
	psd, err := pkcs7.Unmarshal(sig)
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
	indirect := new(SpcIndirectDataContentMsi)
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
	msisig := &MSISignature{
		TimestampedSignature: ts,
		Indirect:             indirect,
		HashFunc:             hash,
		OpusInfo:             opus,
	}
	if !skipDigests {
		imprint, prehash, err := DigestMSI(cdf, hash, exsig != nil)
		if err != nil {
			return nil, err
		}
		if exsig != nil && !hmac.Equal(prehash, exsig) {
			return nil, fmt.Errorf("MSI extended digest mismatch: %x != %x", prehash, exsig)
		}
		if !hmac.Equal(imprint, indirect.MessageDigest.Digest) {
			return nil, fmt.Errorf("MSI digest mismatch: %x != %x", imprint, indirect.MessageDigest.Digest)
		}
	}
	return msisig, nil
}

// Calculate the digest (imprint) of a MSI file. If extended is true then the
// MsiDigitalSignatureEx value is also hashed and returned.
func DigestMSI(cdf *comdoc.ComDoc, hash crypto.Hash, extended bool) (imprint, prehash []byte, err error) {
	d := hash.New()
	if extended {
		prehash, err = PrehashMSI(cdf, hash)
		if err != nil {
			return nil, nil, err
		}
		d.Write(prehash)
	}
	if err := hashMsiDir(cdf, cdf.RootStorage(), d); err != nil {
		return nil, nil, err
	}
	imprint = d.Sum(nil)
	return
}

// Calculates the MsiDigitalSignatureEx blob for a MSI file
func PrehashMSI(cdf *comdoc.ComDoc, hash crypto.Hash) ([]byte, error) {
	d2 := hash.New()
	if err := prehashMsiDir(cdf, cdf.RootStorage(), d2); err != nil {
		return nil, err
	}
	return d2.Sum(nil), nil
}

// Recursively hash a MSI directory (storage)
func hashMsiDir(cdf *comdoc.ComDoc, parent *comdoc.DirEnt, d io.Writer) error {
	files, err := cdf.ListDir(parent)
	if err != nil {
		return err
	}
	sortMsiFiles(files)
	for _, item := range files {
		name := item.Name()
		if name == msiDigitalSignature || name == msiDigitalSignatureEx {
			continue
		}
		switch item.Type {
		case comdoc.DirStream:
			r, err := cdf.ReadStream(item)
			if err != nil {
				return err
			}
			if _, err := io.Copy(d, r); err != nil {
				return err
			}
		case comdoc.DirStorage:
			if err := hashMsiDir(cdf, item, d); err != nil {
				return err
			}
		}
	}
	_, _ = d.Write(parent.UID[:])
	return nil
}

// Recursively hash a MSI directory's extended metadata
func prehashMsiDir(cdf *comdoc.ComDoc, parent *comdoc.DirEnt, d io.Writer) error {
	files, err := cdf.ListDir(parent)
	if err != nil {
		return err
	}
	sortMsiFiles(files)
	prehashMsiDirent(parent, d)
	for _, item := range files {
		name := item.Name()
		if name == msiDigitalSignature || name == msiDigitalSignatureEx {
			continue
		}
		switch item.Type {
		case comdoc.DirStream:
			prehashMsiDirent(item, d)
		case comdoc.DirStorage:
			if err := prehashMsiDir(cdf, item, d); err != nil {
				return err
			}
		}
	}
	return nil
}

// Hash a MSI stream's extended metadata
func prehashMsiDirent(item *comdoc.DirEnt, d io.Writer) {
	buf := bytes.NewBuffer(make([]byte, 0, 128))
	_ = binary.Write(buf, binary.LittleEndian, item.RawDirEnt)
	enc := buf.Bytes()
	// Name
	if item.Type != comdoc.DirRoot {
		_, _ = d.Write(enc[:item.NameLength-2])
	}
	// UID
	if item.Type == comdoc.DirRoot || item.Type == comdoc.DirStorage {
		_, _ = d.Write(item.UID[:])
	}
	// Size
	if item.Type == comdoc.DirStream {
		_, _ = d.Write(enc[120:124])
	}
	// flags
	_, _ = d.Write(enc[96:100])
	// ctime, mtime
	if item.Type != comdoc.DirRoot {
		_, _ = d.Write(enc[100:116])
	}
}

// Sort a list of MSI streams in the order needed for hashing
func sortMsiFiles(files []*comdoc.DirEnt) {
	sort.Slice(files, func(i, j int) bool {
		a, b := files[i], files[j]
		n := a.NameLength
		if b.NameLength < n {
			n = b.NameLength
		}
		// do a comparison of the utf16 in its original LE form
		for k := uint16(0); k < n; k++ {
			x, y := a.NameRunes[k], b.NameRunes[k]
			x1, y1 := x&0xff, y&0xff
			if x1 != y1 {
				return x1 < y1
			}
			x2, y2 := x>>8, y>>8
			if x2 != y2 {
				return x2 < y2
			}
		}
		return a.NameLength > b.NameLength // yes, greater than
	})
}
