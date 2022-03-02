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

package pgptools

import (
	"bytes"
	"errors"
	"io"

	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
)

const maxLiteralSize = (1 << 31) - 512 // int32_max minus some room for the literal data header

// MergeSignature combines a detached signature with a cleartext message and writes it as an inline signed message with optional ASCII armor
func MergeSignature(w io.Writer, sig []byte, message io.Reader, withArmor bool, filename string) (err error) {
	var armorer io.WriteCloser = nopCloseWriter{w}
	if withArmor {
		armorer, err = armor.Encode(w, "PGP MESSAGE", nil)
		if err != nil {
			return err
		}
	}
	// write one-pass signature header
	if err := writeOnePass(armorer, sig); err != nil {
		return err
	}
	// write literal data
	if size := getSize(message); size >= 0 {
		if err := serializeLiteral(armorer, message, size, filename); err != nil {
			return err
		}
	} else {
		litWriter, err := packet.SerializeLiteral(nopCloseWriter{armorer}, true, filename, 0)
		if err != nil {
			return err
		}
		if _, err := io.Copy(litWriter, message); err != nil {
			return err
		}
		if err := litWriter.Close(); err != nil {
			return err
		}
	}
	// write signature
	if _, err := armorer.Write(sig); err != nil {
		return err
	}
	return armorer.Close()
}

// write a one-pass signature header with the fields copied from the detached signature in sig
func writeOnePass(w io.Writer, sig []byte) error {
	genpkt, err := packet.Read(bytes.NewReader(sig))
	if err != nil {
		return err
	}
	// parse
	op := packet.OnePassSignature{IsLast: true}
	switch pkt := genpkt.(type) {
	case *packet.SignatureV3:
		op.SigType = pkt.SigType
		op.Hash = pkt.Hash
		op.PubKeyAlgo = pkt.PubKeyAlgo
		op.KeyId = pkt.IssuerKeyId
	case *packet.Signature:
		op.SigType = pkt.SigType
		op.Hash = pkt.Hash
		op.PubKeyAlgo = pkt.PubKeyAlgo
		if pkt.IssuerKeyId != nil {
			op.KeyId = *pkt.IssuerKeyId
		}
	default:
		return errors.New("not a PGP signature")
	}
	return op.Serialize(w)
}

// write size bytes from r into w as a literal data packet
func serializeLiteral(w io.Writer, r io.Reader, size int32, filename string) error {
	if len(filename) > 255 {
		filename = filename[:255]
	}
	var buf bytes.Buffer
	buf.WriteByte('b')                 // binary mode
	buf.WriteByte(byte(len(filename))) // filename
	buf.WriteString(filename)          // filename
	buf.Write([]byte{0, 0, 0, 0})      // timestamp
	packetType := 11                   // literal data
	psize := int64(size) + int64(buf.Len())
	if psize > (2<<31)-1 {
		return errors.New("literal too big")
	}
	if err := serializeHeader(w, packetType, int(psize)); err != nil {
		return err
	}
	if _, err := w.Write(buf.Bytes()); err != nil {
		return err
	}
	_, err := io.CopyN(w, r, int64(size))
	return err
}

// get the size from a reader if it's seekable and not too big to fit in a single literal data packet, otherwise returns -1
func getSize(r io.Reader) int32 {
	seek, ok := r.(io.Seeker)
	if !ok {
		return -1
	}
	start, err := seek.Seek(0, io.SeekCurrent)
	if err != nil {
		return -1
	}
	end, err := seek.Seek(0, io.SeekEnd)
	if err != nil {
		return -1
	}
	_, err = seek.Seek(start, io.SeekStart)
	if err != nil {
		return -1
	}
	size := end - start
	if size > maxLiteralSize {
		return -1
	}
	return int32(size)
}

// serializeHeader writes an OpenPGP packet header to w. See RFC 4880, section
// 4.2.
func serializeHeader(w io.Writer, ptype int, length int) (err error) {
	var buf [6]byte
	var n int

	buf[0] = 0x80 | 0x40 | byte(ptype)
	if length < 192 {
		buf[1] = byte(length)
		n = 2
	} else if length < 8384 {
		length -= 192
		buf[1] = 192 + byte(length>>8)
		buf[2] = byte(length)
		n = 3
	} else {
		buf[1] = 255
		buf[2] = byte(length >> 24)
		buf[3] = byte(length >> 16)
		buf[4] = byte(length >> 8)
		buf[5] = byte(length)
		n = 6
	}

	_, err = w.Write(buf[:n])
	return
}

type nopCloseWriter struct {
	io.Writer
}

func (nopCloseWriter) Close() error {
	return nil
}
