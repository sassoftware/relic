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
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
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
	pkt, err := readOneSignature(signature)
	if err != nil {
		return nil, err
	}
	key := findKey(keyring, pkt)
	if key == nil {
		if pkt.IssuerKeyId != nil {
			return nil, ErrNoKey(*pkt.IssuerKeyId)
		}
		return nil, ErrNoKey(0)
	}
	// calculate hash
	hash := pkt.Hash
	if !hash.Available() {
		return nil, fmt.Errorf("signature digest %s is unknown or unavailable", hash)
	}
	d := hash.New()
	if _, err := io.Copy(d, signed); err != nil {
		return nil, err
	}
	// check signature
	err = key.PublicKey.VerifySignature(d, pkt)
	return &PgpSignature{
		Key:          key,
		CreationTime: pkt.CreationTime,
		Hash:         hash,
	}, err
}

// Verify a cleartext PGP signature in "signature" using keys from "keyring".
// Returns a value of ErrNoKey in the key cannot be found. If "cleartext" is
// not nil, then write the embedded cleartext as it is verified.
func VerifyClearSign(signature io.Reader, cleartext io.Writer, keyring openpgp.EntityList) (*PgpSignature, error) {
	blob, err := io.ReadAll(signature)
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
		cleartext = io.Discard
	}
	if _, err := io.Copy(cleartext, md.UnverifiedBody); err != nil {
		return nil, err
	}
	// reading UnverifiedBody in full triggers the signature validation
	sig := &PgpSignature{Key: md.SignedBy}
	if md.Signature != nil {
		sig.CreationTime = md.Signature.CreationTime
		sig.Hash = md.Signature.Hash
	} else {
		return nil, errors.New("unsupported inline signature")
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
