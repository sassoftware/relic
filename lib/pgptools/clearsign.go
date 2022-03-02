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
	"bufio"
	"bytes"
	"crypto"
	"errors"
	"io"
	"io/ioutil"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/clearsign"
	"golang.org/x/crypto/openpgp/packet"
)

var sigHeader = []byte("-----BEGIN PGP SIGNATURE-----")
var crlf = []byte("\r\n")

// Do a cleartext signature, signing the document in "message" and writing the result to "w"
func ClearSign(w io.Writer, signer *openpgp.Entity, message io.Reader, config *packet.Config) error {
	e, err := clearsign.Encode(w, signer.PrivateKey, config)
	if err != nil {
		return err
	}
	if _, err := io.Copy(e, message); err != nil {
		return err
	}
	if err := e.Close(); err != nil {
		return err
	}
	_, err = w.Write(crlf)
	return err
}

// Do a cleartext signature but skip writing the embedded original document and
// write just the signature block to "w"
func DetachClearSign(w io.Writer, signer *openpgp.Entity, message io.Reader, config *packet.Config) error {
	readPipe, writePipe := io.Pipe()
	done := make(chan error)
	go func() {
		tail, err := tailClearSign(readPipe)
		if err == nil {
			_, err = w.Write(tail)
		}
		done <- err
	}()
	err := ClearSign(writePipe, signer, message, config)
	_ = writePipe.CloseWithError(err)
	return <-done
}

// Consume bytes from a Reader, returning only the signature block at the end
func tailClearSign(r io.Reader) ([]byte, error) {
	s := bufio.NewScanner(r)
	out := bytes.NewBuffer(make([]byte, 0, 1024))
	copying := false
	for s.Scan() {
		line := s.Bytes()
		if copying || bytes.Equal(line, sigHeader) {
			copying = true
			out.Write(line)
			out.WriteString("\r\n")
		}
	}
	return out.Bytes(), s.Err()
}

// Create a cleartext signature by merging an original document stream in
// "message" with a detached signature in "sig" produced by DetachClearSign()
func MergeClearSign(w io.Writer, sig []byte, message io.Reader) error {
	config, err := configFromSig(sig)
	if err != nil {
		return err
	}
	// Make a fake entity just to get ClearSign() to produce the right framework
	signer := &openpgp.Entity{PrivateKey: &packet.PrivateKey{
		PrivateKey: fakeSigner{},
		PublicKey:  packet.PublicKey{PubKeyAlgo: packet.PubKeyAlgoRSA},
	}}

	out := bufio.NewWriter(w)
	defer out.Flush()
	readPipe, writePipe := io.Pipe()
	done := make(chan error)
	go func() {
		done <- headClearSign(readPipe, out)
	}()

	err = ClearSign(writePipe, signer, message, config)
	_ = writePipe.CloseWithError(err)
	if err := <-done; err != nil {
		return err
	}

	_, err = out.Write(sig)
	return err
}

// Copy bytes, stopping before the signature block at the end
func headClearSign(r io.Reader, w io.Writer) error {
	s := bufio.NewScanner(r)
	for s.Scan() {
		line := s.Bytes()
		if bytes.Equal(line, sigHeader) {
			// found the end of the document, drain the rest of the reader
			_, err := io.Copy(ioutil.Discard, r)
			return err
		}
		if _, err := w.Write(line); err != nil {
			return err
		}
		if _, err := w.Write(crlf); err != nil {
			return err
		}
	}
	if s.Err() != nil {
		return s.Err()
	}
	return errors.New("Signature block not found")
}

// Set up a pgp signature config based on the hash algorithm in an existing
// signature
func configFromSig(sigarmor []byte) (*packet.Config, error) {
	block, err := armor.Decode(bytes.NewReader(sigarmor))
	if err != nil {
		return nil, err
	}
	if block.Type != "PGP SIGNATURE" {
		return nil, errors.New("Not a PGP signature")
	}
	parser := packet.NewReader(block.Body)
	pkt, err := parser.Next()
	if err != nil {
		return nil, errors.New("Not a PGP signature")
	}
	var hashFunc crypto.Hash
	switch sig := pkt.(type) {
	case *packet.Signature:
		hashFunc = sig.Hash
	case *packet.SignatureV3:
		hashFunc = sig.Hash
	default:
		return nil, errors.New("Not a PGP signature")
	}
	return &packet.Config{DefaultHash: hashFunc}, nil
}

type fakeSigner struct{}

func (fakeSigner) Public() crypto.PublicKey {
	return nil
}

func (fakeSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return []byte("fake signature here"), nil
}
