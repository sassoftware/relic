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
	"crypto"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"time"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/clearsign"
	"golang.org/x/crypto/openpgp/packet"
)

type PgpSignature struct {
	Key          *openpgp.Key
	CreationTime time.Time
	Hash         crypto.Hash
}

// Verify a detached PGP signature in "signature" over the document in
// "signed", using keys from "keyring". Returns a value of ErrNoKey if the key
// cannot be found.
func VerifyDetached(signature, signed io.Reader, keyring openpgp.EntityList) (*PgpSignature, error) {
	packetReader := packet.NewReader(signature)
	genpkt, err := packetReader.Next()
	if err == io.EOF {
		return nil, errors.New("no PGP signature found")
	} else if err != nil {
		return nil, err
	}
	// parse
	var hash crypto.Hash
	var keyID uint64
	var creationTime time.Time
	switch pkt := genpkt.(type) {
	case *packet.SignatureV3:
		hash = pkt.Hash
		keyID = pkt.IssuerKeyId
		creationTime = pkt.CreationTime
	case *packet.Signature:
		if pkt.IssuerKeyId == nil {
			return nil, errors.New("Missing keyId in signature")
		}
		hash = pkt.Hash
		keyID = *pkt.IssuerKeyId
		creationTime = pkt.CreationTime
	default:
		return nil, errors.New("not a PGP signature")
	}
	// find key
	keys := keyring.KeysById(keyID)
	if len(keys) == 0 {
		return nil, ErrNoKey(keyID)
	}
	// calculate hash
	if !hash.Available() {
		return nil, errors.New("signature uses unknown digest")
	}
	d := hash.New()
	if _, err := io.Copy(d, signed); err != nil {
		return nil, err
	}
	// check signature
	switch pkt := genpkt.(type) {
	case *packet.SignatureV3:
		err = keys[0].PublicKey.VerifySignatureV3(d, pkt)
	case *packet.Signature:
		err = keys[0].PublicKey.VerifySignature(d, pkt)
	}
	return &PgpSignature{&keys[0], creationTime, hash}, err
}

// Verify a cleartext PGP signature in "signature" using keys from "keyring".
// Returns a value of ErrNoKey in the key cannot be found. If "cleartext" is
// not nil, then write the embedded cleartext as it is verified.
func VerifyClearSign(signature io.Reader, cleartext io.Writer, keyring openpgp.EntityList) (*PgpSignature, error) {
	blob, err := ioutil.ReadAll(signature)
	if err != nil {
		return nil, err
	}
	csblock, rest := clearsign.Decode(blob)
	if csblock == nil {
		return nil, errors.New("malformed clearsign signature")
	} else if bytes.Contains(rest, []byte("-----BEGIN")) {
		return nil, errors.New("clearsign contains multiple documents")
	}
	if cleartext != nil {
		if _, err := cleartext.Write(csblock.Bytes); err != nil {
			return nil, err
		}
	}
	sig, err := VerifyDetached(csblock.ArmoredSignature.Body, bytes.NewReader(csblock.Bytes), keyring)
	return sig, err
}

// Verify an inline PGP signature in "signature" using keys from "keyring".
// Returns a value of ErrNoKey if the key cannot be found. If "cleartext" is
// not nil, then write the embedded cleartext as it is verified.
func VerifyInline(signature io.Reader, cleartext io.Writer, keyring openpgp.EntityList) (*PgpSignature, error) {
	md, err := openpgp.ReadMessage(signature, keyring, nil, nil)
	if err == io.EOF {
		return nil, ErrNoContent{}
	} else if err != nil {
		return nil, err
	} else if md.SignedBy == nil {
		return nil, ErrNoKey(md.SignedByKeyId)
	}
	if cleartext == nil {
		cleartext = ioutil.Discard
	}
	if _, err := io.Copy(cleartext, md.UnverifiedBody); err != nil {
		return nil, err
	}
	// reading UnverifiedBody in full triggers the signature validation
	sig := &PgpSignature{Key: md.SignedBy}
	if md.Signature != nil {
		sig.CreationTime = md.Signature.CreationTime
		sig.Hash = md.Signature.Hash
	} else if md.SignatureV3 != nil {
		sig.CreationTime = md.SignatureV3.CreationTime
		sig.Hash = md.Signature.Hash
	}
	return sig, md.SignatureError
}

// Returned by Verify* functions when the key used for signing is not in the
// keyring. The value is the KeyID of the missing key.
type ErrNoKey uint64

func (e ErrNoKey) Error() string {
	return fmt.Sprintf("keyId %x not found", uint64(e))
}

// Returned by VerifyInline if the signature is actually a detached signature
type ErrNoContent struct{}

func (ErrNoContent) Error() string {
	return "missing content for detached signature"
}
