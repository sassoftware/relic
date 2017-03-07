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
	"crypto/x509"
	"debug/pe"
	"encoding/asn1"
	"encoding/binary"
	"errors"

	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/binpatch"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/pkcs7"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/x509tools"
)

// Sign the digest and return an Authenticode structure
func (pd *PEDigest) Sign(privKey crypto.Signer, certs []*x509.Certificate) (*pkcs7.ContentInfoSignedData, error) {
	alg, ok := x509tools.PkixDigestAlgorithm(pd.Hash)
	if !ok {
		return nil, errors.New("unsupported digest algorithm")
	}
	var indirect SpcIndirectDataContentPe
	indirect.Data.Type = OidSpcPeImageData
	//indirect.Data.Value.Flags = asn1.BitString{[]byte{0x80}, 1}
	indirect.MessageDigest.Digest = pd.Imprint
	indirect.MessageDigest.DigestAlgorithm = alg
	if len(pd.PageHashes) > 0 {
		if err := pd.imprintPageHashes(&indirect); err != nil {
			return nil, err
		}
	} else {
		indirect.Data.Value.File.File.Unicode = "<<<Obsolete>>>"
	}
	sig := pkcs7.NewBuilder(privKey, certs, pd.Hash)
	if err := sig.SetContent(OidSpcIndirectDataContent, indirect); err != nil {
		return nil, err
	}
	if err := sig.AddAuthenticatedAttribute(OidSpcSpOpusInfo, SpcSpOpusInfo{}); err != nil {
		return nil, err
	}
	return sig.Sign()
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
	attrRaw := asn1.RawValue{Tag: asn1.TagSet, IsCompound: true, Bytes: blob}
	serdata, err := asn1.Marshal(attrRaw)
	if err != nil {
		return err
	}
	indirect.Data.Value.File.Moniker.ClassId = SpcUuidPageHashes
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
	binary.Write(&buf, binary.LittleEndian, info)
	buf.Write(sig)
	buf.Write(make([]byte, padded-len(sig)))
	// pack data directory
	certTbl := buf.Bytes()
	var dd pe.DataDirectory
	if pd.OrigSize >= (1 << 32) {
		return nil, errors.New("PE file is too big")
	}
	dd.VirtualAddress = uint32(pd.OrigSize)
	dd.Size = uint32(len(certTbl))
	var buf2 bytes.Buffer
	binary.Write(&buf2, binary.LittleEndian, dd)
	// make patch
	patch := binpatch.New()
	patch.Add(pd.markers.posDDCert, 8, buf2.Bytes())
	patch.Add(pd.OrigSize, uint32(pd.markers.certSize), certTbl)
	return patch, nil
}

type certInfo struct {
	Length          uint32
	Revision        uint16
	CertificateType uint16
}
