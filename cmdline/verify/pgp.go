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

package verify

import (
	"crypto"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"time"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
)

type pgpSignature struct {
	Signer       *openpgp.Entity
	CreationTime time.Time
	KeyId        uint64
}

func verifyPgp(f *os.File) error {
	var first [1]byte
	if _, err := f.Read(first[:]); err != nil {
		return err
	}
	if _, err := f.Seek(0, 0); err != nil {
		return err
	}
	// remove ASCII armor
	reader := io.Reader(f)
	if first[0] == '-' {
		block, err := armor.Decode(reader)
		if err != nil {
			return err
		}
		reader = block.Body
	}
	if argContent != "" {
		// detached signature
		f, err := os.Open(argContent)
		if err != nil {
			return err
		}
		defer f.Close()
		sig, err := checkDetached(trustedPgp, reader, f)
		if err != nil {
			return err
		}
		fmt.Printf("%s: OK - %s(%x) [%s]\n", f.Name(), entityName(sig.Signer), sig.KeyId, sig.CreationTime)
	} else {
		// inline signature
		md, err := openpgp.ReadMessage(reader, trustedPgp, nil, nil)
		if err == io.EOF {
			return errors.New("detached signature requires --content")
		} else if err != nil {
			return err
		} else if md.SignedBy == nil {
			return fmt.Errorf("unknown signer with keyId %x", md.SignedByKeyId)
		}
		if _, err := io.Copy(ioutil.Discard, md.UnverifiedBody); err != nil {
			return err
		}
		if md.SignatureError != nil {
			return err
		}
		var creationTime time.Time
		if md.Signature != nil {
			creationTime = md.Signature.CreationTime
		} else if md.SignatureV3 != nil {
			creationTime = md.SignatureV3.CreationTime
		}
		fmt.Printf("%s: OK - %s(%x) [%s]\n", f.Name(), entityName(md.SignedBy.Entity), md.SignedByKeyId, creationTime)
	}
	return nil
}

func checkDetached(keyring openpgp.KeyRing, signature, signed io.Reader) (sig pgpSignature, err error) {
	packetReader := packet.NewReader(signature)
	genpkt, err := packetReader.Next()
	if err != nil {
		return sig, err
	}
	// parse
	var hash crypto.Hash
	var keyId uint64
	switch pkt := genpkt.(type) {
	case *packet.SignatureV3:
		hash = pkt.Hash
		keyId = pkt.IssuerKeyId
		sig.CreationTime = pkt.CreationTime
	case *packet.Signature:
		if pkt.IssuerKeyId == nil {
			return sig, errors.New("Missing keyId in signature")
		}
		hash = pkt.Hash
		keyId = *pkt.IssuerKeyId
		sig.CreationTime = pkt.CreationTime
	default:
		return sig, errors.New("not a PGP detached signature")
	}
	_, err = packetReader.Next()
	if err != io.EOF {
		return sig, errors.New("trailing garbage after signature")
	}
	// find key
	keys := keyring.KeysById(keyId)
	if len(keys) == 0 {
		return sig, fmt.Errorf("keyid %x not found", keyId)
	}
	sig.Signer = keys[0].Entity
	// calculate hash
	if !hash.Available() {
		return sig, errors.New("signature uses unknown digest")
	}
	d := hash.New()
	if _, err := io.Copy(d, signed); err != nil {
		return sig, err
	}
	// check signature
	switch pkt := genpkt.(type) {
	case *packet.SignatureV3:
		err = keys[0].PublicKey.VerifySignatureV3(d, pkt)
	case *packet.Signature:
		err = keys[0].PublicKey.VerifySignature(d, pkt)
	default:
		panic("unreachable")
	}
	return sig, err
}

func entityName(entity *openpgp.Entity) string {
	if entity == nil {
		return ""
	}
	var name string
	for _, ident := range entity.Identities {
		if name == "" {
			name = ident.Name
		}
		if ident.SelfSignature.IsPrimaryId != nil && *ident.SelfSignature.IsPrimaryId {
			return ident.Name
		}
	}
	return name
}
