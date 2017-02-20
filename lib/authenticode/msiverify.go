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
	"sort"

	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/comdoc"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/pkcs7"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/pkcs9"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/x509tools"
)

type MSISignature struct {
	pkcs9.TimestampedSignature
	Indirect *SpcIndirectDataContentMsi
	HashFunc crypto.Hash
}

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
				sig, err = ioutil.ReadAll(r)
			}
			if err != nil {
				return nil, err
			}
		} else if name == msiDigitalSignatureEx {
			r, err := cdf.ReadStream(item)
			if err == nil {
				exsig, err = ioutil.ReadAll(r)
			}
			if err != nil {
				return nil, err
			}
		}
	}
	if len(sig) == 0 {
		return nil, errors.New("MSI is not signed")
	}
	var psd pkcs7.ContentInfoSignedData
	if rest, err := asn1.Unmarshal(sig, &psd); err != nil {
		panic(err)
		return nil, err
	} else if len(bytes.TrimRight(rest, "\x00")) != 0 {
		return nil, errors.New("trailing garbage after signature")
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
		panic(err)
		return nil, err
	}
	hash, ok := x509tools.PkixDigestToHash(indirect.MessageDigest.DigestAlgorithm)
	if !ok || !hash.Available() {
		return nil, fmt.Errorf("unsupported hash algorithm %s", indirect.MessageDigest.DigestAlgorithm)
	}
	msisig := &MSISignature{
		TimestampedSignature: ts,
		Indirect:             indirect,
		HashFunc:             hash,
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

func PrehashMSI(cdf *comdoc.ComDoc, hash crypto.Hash) ([]byte, error) {
	d2 := hash.New()
	if err := prehashMsiDir(cdf, cdf.RootStorage(), d2); err != nil {
		return nil, err
	}
	return d2.Sum(nil), nil
}

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
	d.Write(parent.Uid[:])
	return nil
}

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

func prehashMsiDirent(item *comdoc.DirEnt, d io.Writer) {
	buf := bytes.NewBuffer(make([]byte, 0, 128))
	if err := binary.Write(buf, binary.LittleEndian, item.RawDirEnt); err != nil {
		panic(err)
	}
	enc := buf.Bytes()
	// Name
	if item.Type != comdoc.DirRoot {
		d.Write(enc[:item.NameLength-2])
	}
	// UID
	if item.Type == comdoc.DirRoot || item.Type == comdoc.DirStorage {
		d.Write(item.Uid[:])
	}
	// Size
	if item.Type == comdoc.DirStream {
		d.Write(enc[120:124])
	}
	// flags
	d.Write(enc[96:100])
	// ctime, mtime
	if item.Type != comdoc.DirRoot {
		d.Write(enc[100:116])
	}
}

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
