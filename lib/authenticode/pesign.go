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
	"encoding/binary"
	"errors"
	"io"

	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/pkcs7"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/x509tools"
)

type Fileish interface {
	io.Reader
	io.ReaderAt
	io.Writer
	io.WriterAt
	io.Seeker
	io.Closer
}

func SignImprint(digest []byte, privKey crypto.Signer, certs []*x509.Certificate, hash crypto.Hash) (*pkcs7.ContentInfoSignedData, error) {
	alg, ok := x509tools.PkixDigestAlgorithm(hash)
	if !ok {
		return nil, errors.New("unsupported digest algorithm")
	}
	var indirect SpcIndirectDataContent
	indirect.Data.Type = OidSpcPeImageData
	//indirect.Data.Value.Flags = asn1.BitString{[]byte{0x80}, 1}
	indirect.Data.Value.File.File.Unicode = "<<<Obsolete>>>"
	indirect.MessageDigest.Digest = digest
	indirect.MessageDigest.DigestAlgorithm = alg
	sig := pkcs7.NewBuilder(privKey, certs, hash)
	if err := sig.SetContent(OidSpcIndirectDataContent, indirect); err != nil {
		return nil, err
	}
	if err := sig.AddAuthenticatedAttribute(OidSpcSpOpusInfo, SpcSpOpusInfo{}); err != nil {
		return nil, err
	}
	return sig.Sign()
}

func InsertPESignature(f Fileish, sig []byte) error {
	m := new(peMarkers)
	if err := parseCoffHeader(f, m); err != nil {
		return err
	}
	if err := findCertTable(f, m); err != nil {
		return err
	}
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
	if m.sizeOfCerts != 0 {
		panic("todo")
	} else {
		n, err := f.Seek(0, io.SeekEnd)
		if err != nil {
			return err
		}
		if n >= (1 << 32) {
			return errors.New("PE file is too big")
		}
		dd.VirtualAddress = uint32(n)
	}
	dd.Size = uint32(buf.Len())
	if _, err := f.Write(buf.Bytes()); err != nil {
		return err
	}
	// go back and update the headers
	if _, err := f.Seek(m.posDDCert, 0); err != nil {
		return err
	}
	if err := binary.Write(f, binary.LittleEndian, dd); err != nil {
		return err
	}
	// TODO: checksum
	return nil
}

type certInfo struct {
	Length          uint32
	Revision        uint16
	CertificateType uint16
}
