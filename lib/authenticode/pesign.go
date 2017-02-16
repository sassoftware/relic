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
	"io"

	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/atomicfile"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/pkcs7"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/x509tools"
)

func SignImprint(digest []byte, hash crypto.Hash, pagehashes []byte, pagehashfunc crypto.Hash, privKey crypto.Signer, certs []*x509.Certificate) (*pkcs7.ContentInfoSignedData, error) {
	alg, ok := x509tools.PkixDigestAlgorithm(hash)
	if !ok {
		return nil, errors.New("unsupported digest algorithm")
	}
	var indirect SpcIndirectDataContent
	indirect.Data.Type = OidSpcPeImageData
	//indirect.Data.Value.Flags = asn1.BitString{[]byte{0x80}, 1}
	indirect.MessageDigest.Digest = digest
	indirect.MessageDigest.DigestAlgorithm = alg
	if len(pagehashes) > 0 {
		if err := imprintPageHashes(&indirect, pagehashes, pagehashfunc); err != nil {
			return nil, err
		}
	} else {
		indirect.Data.Value.File.File.Unicode = "<<<Obsolete>>>"
	}
	sig := pkcs7.NewBuilder(privKey, certs, hash)
	if err := sig.SetContent(OidSpcIndirectDataContent, indirect); err != nil {
		return nil, err
	}
	if err := sig.AddAuthenticatedAttribute(OidSpcSpOpusInfo, SpcSpOpusInfo{}); err != nil {
		return nil, err
	}
	return sig.Sign()
}

func imprintPageHashes(indirect *SpcIndirectDataContent, pagehashes []byte, hash crypto.Hash) error {
	var attr SpcAttributePageHashes
	switch hash {
	case crypto.SHA1:
		attr.Type = OidSpcPageHashV1
	case crypto.SHA256:
		attr.Type = OidSpcPageHashV2
	default:
		return errors.New("unsupported page hash type")
	}
	attr.Hashes = make([][]byte, 1)
	attr.Hashes[0] = pagehashes
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

func InsertPESignature(f atomicfile.Fileish, sig []byte) error {
	// pack new cert table
	padded := (len(sig) + 7) / 8 * 8
	info := certInfo{
		Length:          uint32(8 + padded),
		Revision:        0x0200,
		CertificateType: 0x0002,
	}
	var buf bytes.Buffer
	var dd pe.DataDirectory
	binary.Write(&buf, binary.LittleEndian, info)
	buf.Write(sig)
	buf.Write(make([]byte, padded-len(sig)))
	// find a place for it
	fileSize, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		return err
	}
	hvals, err := findSignatures(f)
	if hvals.certSize != 0 {
		if hvals.certStart+hvals.certSize != fileSize {
			// Even though the signature covers data coming after the
			// certificate table, there's no way to actually relocate that data
			// to make room for a bigger or smaller sig without potentially
			// breaking whatever it is the image does with the data.
			return errors.New("can't re-sign an image that has data after the existing signature")
		}
		fileSize = hvals.certStart
	}
	if fileSize >= (1 << 32) {
		return errors.New("PE file is too big")
	}
	if err := f.Truncate(fileSize); err != nil {
		return err
	}
	dd.VirtualAddress = uint32(fileSize)
	dd.Size = uint32(buf.Len())
	if _, err := f.Seek(fileSize, 0); err != nil {
		return err
	}
	if _, err := f.Write(buf.Bytes()); err != nil {
		return err
	}
	// go back and update the headers
	if _, err := f.Seek(hvals.posDDCert, 0); err != nil {
		return err
	}
	if err := binary.Write(f, binary.LittleEndian, dd); err != nil {
		return err
	}
	ck := NewPEChecksum(int(hvals.peStart))
	if _, err := f.Seek(0, 0); err != nil {
		return err
	}
	if _, err := io.Copy(ck, f); err != nil {
		return err
	}
	if _, err := f.WriteAt(ck.Sum(nil), hvals.peStart+88); err != nil {
		return err
	}
	return nil
}

type certInfo struct {
	Length          uint32
	Revision        uint16
	CertificateType uint16
}
