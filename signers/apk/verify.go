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

package apk

import (
	"archive/zip"
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/sassoftware/relic/v7/lib/pkcs7"
	"github.com/sassoftware/relic/v7/lib/pkcs9"
	"github.com/sassoftware/relic/v7/lib/signjar"
	"github.com/sassoftware/relic/v7/lib/x509tools"
	"github.com/sassoftware/relic/v7/lib/zipslicer"
	"github.com/sassoftware/relic/v7/signers"
	"github.com/sassoftware/relic/v7/signers/sigerrors"
)

func verify(f *os.File, opts signers.VerifyOpts) ([]*signers.Signature, error) {
	// verify v2
	inz, block, err := getSigBlock(f)
	if err != nil {
		return nil, err
	}
	var allSigs []*signers.Signature
	for len(block) > 0 {
		if len(block) < 12 {
			return nil, errTruncated
		}
		partSize := binary.LittleEndian.Uint64(block)
		block = block[8:]
		if partSize < 4 || partSize > uint64(len(block)) {
			return nil, errTruncated
		}
		partType := binary.LittleEndian.Uint32(block)
		partBlob := block[4:partSize]
		block = block[partSize:]
		if partType != sigApkV2 {
			continue
		}
		var signerList []apkSigner
		if err := unmarshal(partBlob, &signerList); err != nil {
			return nil, fmt.Errorf("parsing signature block: %w", err)
		} else if len(signerList) == 0 {
			return nil, errors.New("empty APK signing block")
		}
		for i, signer := range signerList {
			sig, err := signer.Verify(nil)
			if err != nil {
				return nil, fmt.Errorf("APK signature #%d: %w", i+1, err)
			}
			allSigs = append(allSigs, sig)
		}
	}
	v2present := len(allSigs) != 0
	// verify v1
	inzr, err := zip.NewReader(f, inz.Size)
	if err != nil {
		return nil, err
	}
	jarSigs, err := signjar.Verify(inzr, false)
	if err != nil {
		if _, ok := err.(sigerrors.NotSignedError); !ok {
			return nil, err
		}
	}
	for _, jarSig := range jarSigs {
		apk := jarSig.SignatureHeader.Get("X-Android-APK-Signed")
		if strings.ContainsRune(apk, '2') && !v2present {
			return nil, errors.New("V1 signature contains X-Android-APK-Signed header but no V2 signature exists")
		}
		allSigs = append(allSigs, &signers.Signature{
			SigInfo:       "v1",
			Hash:          jarSig.Hash,
			X509Signature: &jarSig.TimestampedSignature,
		})
	}
	if len(allSigs) == 0 {
		return nil, sigerrors.NotSignedError{Type: "APK"}
	}
	return allSigs, nil
}

func getSigBlock(f *os.File) (*zipslicer.Directory, []byte, error) {
	size, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		return nil, nil, err
	}
	inz, err := zipslicer.Read(f, size)
	if err != nil {
		return nil, nil, err
	}
	// check that there is stuff between the last file and the start of the directory
	if len(inz.File) == 0 {
		return nil, nil, errors.New("no files in APK")
	}
	sigLoc, err := inz.NextFileOffset()
	if err != nil {
		return nil, nil, err
	}
	if sigLoc == inz.DirLoc {
		// not signed
		return inz, nil, nil
	}
	// read signature block
	blob := make([]byte, inz.DirLoc-sigLoc)
	if _, err := f.ReadAt(blob, sigLoc); err != nil {
		return nil, nil, err
	}
	// check magic
	if !bytes.HasSuffix(blob, []byte(sigMagic)) {
		return nil, nil, errMalformed
	}
	expected := uint64(len(blob) - 8)
	size1 := binary.LittleEndian.Uint64(blob)
	size2 := binary.LittleEndian.Uint64(blob[len(blob)-24:])
	if size1 != expected || size2 != expected {
		return nil, nil, errMalformed
	}
	return inz, blob[8 : len(blob)-24], nil
}

func (s *apkSigner) Verify(inz *zipslicer.Directory) (*signers.Signature, error) {
	if len(s.Signatures) == 0 {
		return nil, errors.New("no signatures in APK signer block")
	}
	// check signatures over SignedData
	publicKey, err := x509.ParsePKIXPublicKey(s.PublicKey)
	if err != nil {
		return nil, err
	}
	var bestHash crypto.Hash
	for _, sig := range s.Signatures {
		hash, err := sig.VerifySignature(publicKey, s.SignedData.Bytes())
		if err != nil {
			return nil, err
		}
		// check them all but only need to report one per signature
		if hash > bestHash {
			bestHash = hash
		}
	}
	// check digests
	var signedData apkSignedData
	if err := unmarshal(s.SignedData, &signedData); err != nil {
		return nil, err
	}
	if len(signedData.Digests) == 0 {
		return nil, errors.New("no digests in APK signed data block")
	}
	if inz != nil {
		hashes := make([]crypto.Hash, len(signedData.Digests))
		for i, digest := range signedData.Digests {
			st, err := sigTypeByID(digest.ID)
			if err != nil {
				return nil, err
			}
			hashes[i] = st.hash
		}
		hasher := newMerkleHasher(hashes)
		for _, f := range inz.File {
			if _, err := f.Dump(hasher); err != nil {
				return nil, err
			}
		}
		digests, err := hasher.Finish(inz, false)
		if err != nil {
			return nil, err
		}
		for i, digest := range signedData.Digests {
			if !hmac.Equal(digest.Value, digests[i]) {
				return nil, fmt.Errorf("digest mismatch for algorithm 0x%04x", digest.ID)
			}
		}
	}
	// identify which certificate is the leaf
	certs, err := signedData.ParseCertificates()
	if err != nil {
		return nil, err
	}
	var leaf *x509.Certificate
	var intermediates []*x509.Certificate
	for _, cert := range certs {
		if bytes.Equal(cert.RawSubjectPublicKeyInfo, s.PublicKey) {
			leaf = cert
		} else {
			intermediates = append(intermediates, cert)
		}
	}
	if leaf == nil {
		return nil, errors.New("public key does not match any certificate")
	}
	return &signers.Signature{
		SigInfo: "v2",
		Hash:    bestHash,
		X509Signature: &pkcs9.TimestampedSignature{
			Signature: pkcs7.Signature{
				Certificate:   leaf,
				Intermediates: intermediates,
			},
		},
	}, nil
}

func (sig *apkSignature) VerifySignature(publicKey interface{}, signedData []byte) (crypto.Hash, error) {
	st, err := sigTypeByID(sig.ID)
	if err != nil {
		return 0, err
	}
	d := st.hash.New()
	d.Write(signedData)
	hashed := d.Sum(nil)
	switch st.alg {
	case x509.RSA:
		pub, ok := publicKey.(*rsa.PublicKey)
		if !ok {
			return 0, errors.New("public key algorithm mismatch")
		}
		if st.pss {
			err = rsa.VerifyPSS(pub, st.hash, hashed, sig.Value, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		} else {
			err = rsa.VerifyPKCS1v15(pub, st.hash, hashed, sig.Value)
		}
		if err != nil {
			return 0, err
		}
	case x509.ECDSA:
		pub, ok := publicKey.(*ecdsa.PublicKey)
		if !ok {
			return 0, errors.New("public key algorithm mismatch")
		}
		esig, err := x509tools.UnmarshalEcdsaSignature(sig.Value)
		if err != nil {
			return 0, err
		}
		if !ecdsa.Verify(pub, hashed, esig.R, esig.S) {
			return 0, errors.New("ECDSA verification failed")
		}
	default:
		return 0, errors.New("unsupported public key algorithm")
	}
	return st.hash, nil
}
