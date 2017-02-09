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
	"bytes"
	"crypto"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"time"

	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/pgptools"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/clearsign"
	"golang.org/x/crypto/openpgp/packet"
)

func verifyPgp(f *os.File) error {
	if len(trustedPgp) == 0 {
		return errors.New("Need one or more PGP keys to validate against; use --cert")
	}
	var first [34]byte
	if _, err := f.Read(first[:]); err != nil {
		return err
	}
	if _, err := f.Seek(0, 0); err != nil {
		return err
	}
	// remove ASCII armor
	reader := io.Reader(f)
	if first[0] == '-' {
		if bytes.HasPrefix(first[:], []byte("-----BEGIN PGP SIGNED MESSAGE-----")) {
			// clearsign
			return verifyPgpClear(f)
		}
		block, err := armor.Decode(reader)
		if err != nil {
			return err
		}
		reader = block.Body
	}
	if argContent != "" {
		// detached signature
		fc, err := os.Open(argContent)
		if err != nil {
			return err
		}
		defer fc.Close()
		return verifyPgpDetached(f, reader, fc)
	} else {
		// inline signature
		return verifyPgpInline(f, reader)
	}
}

func verifyPgpDetached(f *os.File, signature io.Reader, signed io.ReadSeeker) error {
	packetReader := packet.NewReader(signature)
	found := false
	for {
		genpkt, err := packetReader.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}
		// parse
		var hash crypto.Hash
		var keyId uint64
		var creationTime time.Time
		switch pkt := genpkt.(type) {
		case *packet.SignatureV3:
			hash = pkt.Hash
			keyId = pkt.IssuerKeyId
			creationTime = pkt.CreationTime
		case *packet.Signature:
			if pkt.IssuerKeyId == nil {
				return errors.New("Missing keyId in signature")
			}
			hash = pkt.Hash
			keyId = *pkt.IssuerKeyId
			creationTime = pkt.CreationTime
		default:
			continue
		}
		// find key
		keys := trustedPgp.KeysById(keyId)
		if len(keys) == 0 {
			return fmt.Errorf("keyid %x not found", keyId)
		}
		// calculate hash
		if !hash.Available() {
			return errors.New("signature uses unknown digest")
		}
		d := hash.New()
		if _, err := signed.Seek(0, 0); err != nil {
			return err
		}
		if _, err := io.Copy(d, signed); err != nil {
			return err
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
		fmt.Printf("%s: OK - %s(%x) [%s]\n", f.Name(), pgptools.EntityName(keys[0].Entity), keyId, creationTime)
		found = true
	}
	if !found {
		return errors.New("no PGP signatures found")
	}
	return nil
}

func verifyPgpClear(f *os.File) error {
	blob, err := ioutil.ReadAll(f)
	if err != nil {
		return err
	}
	csblock, rest := clearsign.Decode(blob)
	if csblock == nil {
		return errors.New("malformed clearsign signature")
	} else if bytes.Contains(rest, []byte("-----BEGIN")) {
		return errors.New("clearsign contains multiple documents")
	}
	return verifyPgpDetached(f, csblock.ArmoredSignature.Body, bytes.NewReader(csblock.Bytes))
}

func verifyPgpInline(f *os.File, signature io.Reader) error {
	md, err := openpgp.ReadMessage(signature, trustedPgp, nil, nil)
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
	fmt.Printf("%s: OK - %s(%x) [%s]\n", f.Name(), pgptools.EntityName(md.SignedBy.Entity), md.SignedByKeyId, creationTime)
	return nil
}
