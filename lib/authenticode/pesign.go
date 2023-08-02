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
	"context"
	"crypto"
	"debug/pe"
	"encoding/asn1"
	"encoding/binary"
	"errors"

	"github.com/sassoftware/relic/v7/lib/binpatch"
	"github.com/sassoftware/relic/v7/lib/certloader"
	"github.com/sassoftware/relic/v7/lib/pkcs9"
)

// Sign the digest and return an Authenticode structure
func (pd *PEDigest) Sign(ctx context.Context, cert *certloader.Certificate, params *OpusParams) (*binpatch.PatchSet, *pkcs9.TimestampedSignature, error) {
	indirect, err := pd.GetIndirect()
	if err != nil {
		return nil, nil, err
	}
	ts, err := signIndirect(ctx, indirect, pd.Hash, cert, params)
	if err != nil {
		return nil, nil, err
	}
	patch, err := pd.MakePatch(ts.Raw)
	if err != nil {
		return nil, nil, err
	}
	return patch, ts, nil
}

func (pd *PEDigest) GetIndirect() (indirect SpcIndirectDataContentPe, err error) {
	indirect, err = makePeIndirect(pd.Imprint, pd.Hash, OidSpcPeImageData)
	if err != nil {
		return
	}
	if len(pd.PageHashes) > 0 {
		if err2 := pd.imprintPageHashes(&indirect); err2 != nil {
			err = err2
			return
		}
	}
	return
}

func (pd *PEDigest) imprintPageHashes(indirect *SpcIndirectDataContentPe) error {
	var attr SpcAttributePageHashes
	switch pd.Hash {
	case crypto.SHA1:
		attr.Type = OidSpcPageHashV1
	case crypto.SHA256:
		attr.Type = OidSpcPageHashV2
	default:
		return errors.New("unsupported page hash type")
	}
	attr.Hashes = make([][]byte, 1)
	attr.Hashes[0] = pd.PageHashes
	blob, err := asn1.Marshal(attr)
	if err != nil {
		return err
	}
	serdata, err := asn1.Marshal(makeSet(blob))
	if err != nil {
		return err
	}
	indirect.Data.Value.File = SpcLink{}
	indirect.Data.Value.File.Moniker.ClassID = SpcUUIDPageHashes
	indirect.Data.Value.File.Moniker.SerializedData = serdata
	return nil
}

// Create a patchset that will add or replace the signature from a previously
// digested image with a new one
func (pd *PEDigest) MakePatch(sig []byte) (*binpatch.PatchSet, error) {
	// pack new cert table
	padded := (len(sig) + 7) / 8 * 8
	info := certInfo{
		Length:          uint32(8 + padded),
		Revision:        0x0200,
		CertificateType: 0x0002,
	}
	var buf bytes.Buffer
	pad2 := pd.CertStart - pd.OrigSize
	if pad2 != 0 {
		buf.Write(make([]byte, pad2))
	}
	_ = binary.Write(&buf, binary.LittleEndian, info)
	_, _ = buf.Write(sig)
	_, _ = buf.Write(make([]byte, padded-len(sig)))
	// pack data directory
	certTbl := buf.Bytes()
	var dd pe.DataDirectory
	if pd.CertStart >= (1 << 32) {
		return nil, errors.New("PE file is too big")
	}
	dd.VirtualAddress = uint32(pd.CertStart)
	dd.Size = uint32(len(certTbl)) - uint32(pad2)
	var buf2 bytes.Buffer
	_ = binary.Write(&buf2, binary.LittleEndian, dd)
	// make patch
	patch := binpatch.New()
	patch.Add(pd.markers.posDDCert, 8, buf2.Bytes())
	patch.Add(pd.OrigSize, int64(pd.markers.certSize), certTbl)
	return patch, nil
}

type certInfo struct {
	Length          uint32
	Revision        uint16
	CertificateType uint16
}
