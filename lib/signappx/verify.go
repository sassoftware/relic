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

package signappx

import (
	"archive/zip"
	"bytes"
	"crypto/hmac"
	"errors"
	"fmt"
	"io"

	"github.com/sassoftware/relic/v7/lib/authenticode"
	"github.com/sassoftware/relic/v7/lib/pkcs7"
	"github.com/sassoftware/relic/v7/lib/pkcs9"
	"github.com/sassoftware/relic/v7/lib/x509tools"
	"github.com/sassoftware/relic/v7/signers/sigerrors"
)

func Verify(r io.ReaderAt, size int64, skipDigests bool) (*AppxSignature, error) {
	inz, err := zip.NewReader(r, size)
	if err != nil {
		return nil, err
	}
	files := make(zipFiles, len(inz.File))
	for _, file := range inz.File {
		files[file.Name] = file
	}
	sig, err := readSignature(files[appxSignature])
	if err != nil {
		return nil, err
	}
	sig.IsBundle = files[bundleManifestFile] != nil
	if err := verifyFile(files, sig, "AXBM", appxBlockMap); err != nil {
		return nil, err
	}
	if err := verifyFile(files, sig, "AXCI", appxCodeIntegrity); err != nil {
		return nil, err
	}
	if err := verifyFile(files, sig, "AXCT", appxContentTypes); err != nil {
		return nil, err
	}
	if err := verifyBlockMap(inz, files, skipDigests); err != nil {
		return nil, err
	}
	if err := verifyCatalog(files[appxCodeIntegrity], sig); err != nil {
		return nil, err
	}
	if err := verifyMeta(r, size, sig, skipDigests); err != nil {
		return nil, err
	}
	if sig.IsBundle {
		if err := verifyBundle(r, files, sig, skipDigests); err != nil {
			return nil, err
		}
	} else {
		if err := checkManifest(files, sig); err != nil {
			return nil, err
		}
	}
	return sig, nil
}

func readSignature(zf *zip.File) (*AppxSignature, error) {
	if zf == nil {
		return nil, sigerrors.NotSignedError{Type: "appx"}
	}
	blob, err := readZipFile(zf)
	if err != nil {
		return nil, err
	}
	if !bytes.HasPrefix(blob, []byte("PKCX")) {
		return nil, errors.New("invalid appx signature")
	}
	psd, err := pkcs7.Unmarshal(blob[4:])
	if err != nil {
		return nil, fmt.Errorf("invalid appx signature: %w", err)
	}
	if !psd.Content.ContentInfo.ContentType.Equal(authenticode.OidSpcIndirectDataContent) {
		return nil, fmt.Errorf("invalid appx signature: %s", "not an authenticode signature")
	}
	pksig, err := psd.Content.Verify(nil, false)
	if err != nil {
		return nil, fmt.Errorf("invalid appx signature: %w", err)
	}
	ts, err := pkcs9.VerifyOptionalTimestamp(pksig)
	if err != nil {
		return nil, err
	}
	indirect := new(authenticode.SpcIndirectDataContentMsi)
	if err := psd.Content.ContentInfo.Unmarshal(indirect); err != nil {
		return nil, fmt.Errorf("invalid appx signature: %w", err)
	}
	hash, err := x509tools.PkixDigestToHashE(indirect.MessageDigest.DigestAlgorithm)
	if err != nil {
		return nil, err
	}
	digests := indirect.MessageDigest.Digest
	if !bytes.HasPrefix(digests, []byte("APPX")) {
		return nil, errors.New("invalid appx signature")
	}
	digests = digests[4:]
	digestmap := make(map[string][]byte)
	for len(digests) > 0 {
		if len(digests) < 4+hash.Size() {
			return nil, errors.New("invalid appx signature")
		}
		name := string(digests[:4])
		digestmap[name] = digests[4 : 4+hash.Size()]
		digests = digests[4+hash.Size():]
	}
	opus, err := authenticode.GetOpusInfo(ts.SignerInfo)
	if err != nil {
		return nil, err
	}
	return &AppxSignature{
		Signature:  &ts,
		Hash:       hash,
		HashValues: digestmap,
		OpusInfo:   opus,
	}, nil
}

func verifyFile(files zipFiles, sig *AppxSignature, tag, name string) error {
	expected := sig.HashValues[tag]
	zf := files[name]
	if zf == nil {
		if expected == nil {
			return nil
		}
		return fmt.Errorf("appx missing signed file: %s", name)
	} else if expected == nil {
		return fmt.Errorf("appx missing signature for file: %s", name)
	}
	r, err := zf.Open()
	if err != nil {
		return err
	}
	d := sig.Hash.New()
	if _, err := io.Copy(d, r); err != nil {
		return err
	}
	if err := r.Close(); err != nil {
		return err
	}
	calc := d.Sum(nil)
	if !hmac.Equal(calc, expected) {
		return fmt.Errorf("appx digest mismatch for %s: calculated %x != found %x", name, calc, expected)
	}
	return nil
}

func readZipFile(zf *zip.File) ([]byte, error) {
	if zf == nil {
		return nil, errors.New("file not found")
	}
	r, err := zf.Open()
	if err != nil {
		return nil, err
	}
	blob, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	if err := r.Close(); err != nil {
		return nil, err
	}
	return blob, nil
}

func verifyCatalog(zf *zip.File, sig *AppxSignature) error {
	if zf == nil {
		if sig.IsBundle {
			return nil
		}
		return errors.New("missing security catalog")
	}
	blob, err := readZipFile(zf)
	if err != nil {
		return err
	}
	psd, err := pkcs7.Unmarshal(blob)
	if err != nil {
		return fmt.Errorf("security catalog: %w", err)
	}
	if !psd.Content.ContentInfo.ContentType.Equal(authenticode.OidCertTrustList) {
		return fmt.Errorf("security catalog: %s", "not a security catalog")
	}
	pksig, err := psd.Content.Verify(nil, false)
	if err != nil {
		return fmt.Errorf("security catalog: %w", err)
	}
	ts, err := pkcs9.VerifyOptionalTimestamp(pksig)
	if err != nil {
		return fmt.Errorf("security catalog: %w", err)
	}
	if !bytes.Equal(ts.Certificate.Raw, sig.Signature.Certificate.Raw) {
		return fmt.Errorf("security catalog: %s", "catalog signed by different certificate than appx")
	}
	// TODO: figure out what the things in the catalog actually are
	return nil
}
