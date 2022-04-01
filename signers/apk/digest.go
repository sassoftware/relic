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
	"bytes"
	"crypto"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"

	"github.com/sassoftware/relic/v7/lib/binpatch"
	"github.com/sassoftware/relic/v7/lib/certloader"
	"github.com/sassoftware/relic/v7/lib/x509tools"
	"github.com/sassoftware/relic/v7/lib/zipslicer"
)

type Digest struct {
	inz    *zipslicer.Directory
	hash   crypto.Hash
	value  []byte
	sigLoc int64
}

func digestApkStream(r io.Reader, hash crypto.Hash) (*Digest, error) {
	inz, err := zipslicer.ReadZipTar(r)
	if err != nil {
		return nil, err
	}
	hasher := newMerkleHasher([]crypto.Hash{hash})
	for _, f := range inz.File {
		_, err := f.Dump(hasher)
		if err != nil {
			return nil, err
		}
	}
	sigLoc, err := inz.NextFileOffset()
	if err != nil {
		return nil, err
	}
	origDirLoc := inz.DirLoc
	inz.DirLoc = sigLoc
	digests, err := hasher.Finish(inz, true)
	if err != nil {
		return nil, err
	}
	inz.DirLoc = origDirLoc
	return &Digest{
		inz:    inz,
		hash:   hash,
		value:  digests[0],
		sigLoc: sigLoc,
	}, nil
}

func (d *Digest) Sign(cert *certloader.Certificate) (*binpatch.PatchSet, error) {
	// select a signature type
	alg := x509tools.GetPublicKeyAlgorithm(cert.Leaf.PublicKey)
	var st sigType
	for _, s := range sigTypes {
		if s.hash == d.hash && s.alg == alg && !s.pss {
			st = s
			break
		}
		// TODO: PSS
	}
	if st.id == 0 {
		return nil, errors.New("unsupported public key algorithm")
	}
	// build signed data
	sd := apkSignedData{
		Digests: []apkDigest{apkDigest{ID: st.id, Value: d.value}},
	}
	for _, cert := range cert.Chain() {
		sd.Certificates = append(sd.Certificates, cert.Raw)
	}
	signedData, err := marshal(sd)
	if err != nil {
		return nil, err
	}
	// sign
	digest := st.hash.New()
	digest.Write(signedData.Bytes())
	sigv, err := cert.Signer().Sign(rand.Reader, digest.Sum(nil), st.hash)
	if err != nil {
		return nil, err
	}
	// build signer block
	signerList := []apkSigner{apkSigner{
		SignedData: signedData,
		Signatures: []apkSignature{apkSignature{ID: st.id, Value: sigv}},
		PublicKey:  cert.Leaf.RawSubjectPublicKeyInfo,
	}}
	sblob, err := marshal(signerList)
	if err != nil {
		return nil, err
	}
	block := makeSigBlock(sblob)
	// patch
	patchset := binpatch.New()
	origDirLoc := d.inz.DirLoc
	patchset.Add(d.sigLoc, origDirLoc-d.sigLoc, block)
	d.inz.DirLoc = d.sigLoc + int64(len(block))
	var dirEnts, endOfDir bytes.Buffer
	if err := d.inz.WriteDirectory(&dirEnts, &endOfDir, false); err != nil {
		return nil, err
	}
	patchset.Add(origDirLoc+int64(dirEnts.Len()), int64(endOfDir.Len()), endOfDir.Bytes())
	return patchset, nil
}

func makeSigBlock(sblob []byte) []byte {
	block := make([]byte, 8+12+len(sblob)+24)
	// length prefix on signing block, includes the magic suffix but not itself
	binary.LittleEndian.PutUint64(block, uint64(8+4+len(sblob)+8+16))
	// length prefix on the inner block
	binary.LittleEndian.PutUint64(block[8:], uint64(4+len(sblob)))
	// block type
	binary.LittleEndian.PutUint32(block[8+8:], sigApkV2)
	// the block itself
	copy(block[8+8+4:], sblob)
	// magic suffix
	suffix := block[8+8+4+len(sblob):]
	copy(suffix, block[:8])    // length again
	copy(suffix[8:], sigMagic) // magic
	return block
}
