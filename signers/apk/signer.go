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
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/pkg/errors"
	"github.com/sassoftware/relic/lib/certloader"
	"github.com/sassoftware/relic/lib/magic"
	"github.com/sassoftware/relic/lib/pkcs7"
	"github.com/sassoftware/relic/lib/pkcs9"
	"github.com/sassoftware/relic/lib/signjar"
	"github.com/sassoftware/relic/lib/x509tools"
	"github.com/sassoftware/relic/lib/zipslicer"
	"github.com/sassoftware/relic/signers"
	"github.com/sassoftware/relic/signers/sigerrors"
	"github.com/sassoftware/relic/signers/zipbased"
)

// Sign Android packages

var ApkSigner = &signers.Signer{
	Name:      "apk",
	Magic:     magic.FileTypeAPK,
	CertTypes: signers.CertTypeX509,
	Transform: zipbased.Transform,
	Sign:      sign,
	Verify:    verify,
}

const (
	sigMagic = "APK Sig Block 42"
	sigApkV2 = 0x7109871a

	directoryEndSignature = 0x06054b50
	directoryEndLen       = 22
)

type sigType struct {
	id   uint32
	hash crypto.Hash
	alg  x509.PublicKeyAlgorithm
	pss  bool
}

var sigTypes = []sigType{
	sigType{0x0101, crypto.SHA256, x509.RSA, true},    // RSASSA-PSS with SHA2-256 digest
	sigType{0x0102, crypto.SHA512, x509.RSA, true},    // RSASSA-PSS with SHA2-512 digest
	sigType{0x0103, crypto.SHA256, x509.RSA, false},   // RSASSA-PKCS1-v1_5 with SHA2-256 digest
	sigType{0x0104, crypto.SHA512, x509.RSA, false},   // RSASSA-PKCS1-v1_5 with SHA2-512 digest
	sigType{0x0201, crypto.SHA256, x509.ECDSA, false}, // ECDSA with SHA2-256 digest
	sigType{0x0202, crypto.SHA512, x509.ECDSA, false}, // ECDSA with SHA2-512 digest
	sigType{0x0301, crypto.SHA256, x509.DSA, false},   // DSA with SHA2-256 digest
}

var (
	errMalformed = errors.New("malformed APK signing block")
	errTruncated = errors.New("truncated APK signing block sequence")
)

func init() {
	signers.Register(ApkSigner)
}

func sign(r io.Reader, cert *certloader.Certificate, opts signers.SignOpts) ([]byte, error) {
	return nil, errors.New("TODO")
}

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
		signerList, err := splitUint32Exact(partBlob, 1)
		if err != nil {
			return nil, err
		}
		signers, err := splitUint32(signerList[0])
		if err != nil {
			return nil, err
		} else if len(signers) == 0 {
			return nil, errors.New("empty APK signing block")
		}
		for i, signer := range signers {
			sigs, err := verifySigner(f, inz, signer)
			if err != nil {
				return nil, errors.Wrapf(err, "APK signature #%d", i+1)
			}
			allSigs = append(allSigs, sigs...)
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
	lastFile := inz.File[len(inz.File)-1]
	lastSize, err := lastFile.GetTotalSize()
	if err != nil {
		return nil, nil, err
	}
	sigLoc := int64(lastFile.Offset) + lastSize
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

func verifySigner(r io.ReaderAt, inz *zipslicer.Directory, signer []byte) (sigs []*signers.Signature, err error) {
	members, err := splitUint32Exact(signer, 3)
	if err != nil {
		return nil, err
	}
	signedData := members[0]
	certs, err := verifySignedData(r, inz, signedData)
	if err != nil {
		return nil, err
	}
	spki := members[2]
	var leaf *x509.Certificate
	var intermediates []*x509.Certificate
	for _, cert := range certs {
		if bytes.Equal(cert.RawSubjectPublicKeyInfo, spki) {
			leaf = cert
			break
		} else {
			intermediates = append(intermediates, cert)
		}
	}
	if leaf == nil {
		return nil, errors.New("signature public key does not match any certificate")
	}
	signatures, err := splitUint32(members[1])
	if err != nil {
		return nil, err
	}
	if len(signatures) == 0 {
		return nil, errMalformed
	}
	for _, signature := range signatures {
		validated, err := verifySignature(signature, signedData, intermediates, leaf)
		if err != nil {
			return nil, err
		}
		sigs = append(sigs, validated)
	}
	return
}

func verifySignedData(r io.ReaderAt, inz *zipslicer.Directory, signedData []byte) ([]*x509.Certificate, error) {
	members, err := splitUint32Exact(signedData, 3)
	if err != nil {
		return nil, err
	}
	digests, err := splitUint32(members[0])
	if err != nil {
		return nil, err
	}
	certificates, err := splitUint32(members[1])
	if err != nil {
		return nil, err
	}
	// attributes in members[2] not supported (or defined yet?)
	for _, digest := range digests {
		// identify algorithm
		st, value, err := parseSigAlg(digest)
		if err != nil {
			return nil, err
		}
		// compare block digests
		actual, err := merkleDigest(r, inz, st.hash)
		if err != nil {
			return nil, err
		}
		if !hmac.Equal(value, actual) {
			return nil, errors.New("digest mismatch")
		}
	}
	certs := make([]*x509.Certificate, len(certificates))
	for i, der := range certificates {
		certs[i], err = x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
	}
	return certs, nil
}

func verifySignature(signature, signedData []byte, intermediates []*x509.Certificate, leaf *x509.Certificate) (*signers.Signature, error) {
	st, sigv, err := parseSigAlg(signature)
	if err != nil {
		return nil, err
	}
	d := st.hash.New()
	d.Write(signedData)
	hashed := d.Sum(nil)
	switch st.alg {
	case x509.RSA:
		pub, ok := leaf.PublicKey.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("public key algorithm mismatch")
		}
		if st.pss {
			err = rsa.VerifyPSS(pub, st.hash, hashed, sigv, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		} else {
			err = rsa.VerifyPKCS1v15(pub, st.hash, hashed, sigv)
		}
		if err != nil {
			return nil, err
		}
	case x509.ECDSA:
		pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, errors.New("public key algorithm mismatch")
		}
		esig, err := x509tools.UnmarshalEcdsaSignature(sigv)
		if err != nil {
			return nil, err
		}
		if !ecdsa.Verify(pub, hashed, esig.R, esig.S) {
			return nil, errors.New("ECDSA verification failed")
		}
	default:
		return nil, errors.New("unsupported public key algorithm")
	}
	sig := &signers.Signature{
		SigInfo: "v2",
		Hash:    st.hash,
		X509Signature: &pkcs9.TimestampedSignature{
			Signature: pkcs7.Signature{
				Certificate:   leaf,
				Intermediates: intermediates,
			},
		},
	}
	return sig, nil
}

func parseSigAlg(blob []byte) (st sigType, value []byte, err error) {
	if len(blob) < 4 {
		err = errMalformed
		return
	}
	algId := binary.LittleEndian.Uint32(blob)
	for _, alg := range sigTypes {
		if alg.id == algId {
			st = alg
			break
		}
	}
	if st.id == 0 {
		err = fmt.Errorf("unknown signature type 0x%0x", algId)
		return
	}
	values, err := splitUint32Exact(blob[4:], 1)
	if err != nil {
		return
	}
	value = values[0]
	if !st.hash.Available() {
		err = errors.New("unsupported digest type")
		return
	}
	return
}

func splitUint32(blob []byte) (ret [][]byte, err error) {
	for len(blob) > 0 {
		if len(blob) < 4 {
			return nil, errTruncated
		}
		size := binary.LittleEndian.Uint32(blob)
		blob = blob[4:]
		if size > uint32(len(blob)) {
			return nil, errTruncated
		}
		ret = append(ret, blob[:size])
		blob = blob[size:]
	}
	return
}

func splitUint32Exact(blob []byte, count int) (ret [][]byte, err error) {
	ret, err = splitUint32(blob)
	if len(ret) != count {
		return nil, errMalformed
	}
	return
}
