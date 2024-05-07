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
	"errors"
	"fmt"
	"io"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// Return the primary identity name of a PGP entity
func EntityName(entity *openpgp.Entity) string {
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

func readOneSignature(r io.Reader) (*packet.Signature, error) {
	pkt, err := packet.Read(r)
	if err != nil {
		return nil, fmt.Errorf("parsing PGP signature: %w", err)
	}
	if n, _ := r.Read(make([]byte, 1)); n > 0 {
		return nil, errors.New("expected a single PGP signature")
	}
	sig, ok := pkt.(*packet.Signature)
	if !ok {
		return nil, fmt.Errorf("expected a PGP v4 or later signature, not %T", pkt)
	}
	return sig, nil
}

func findKey(el openpgp.EntityList, sig *packet.Signature) *openpgp.Key {
	for _, e := range el {
		if sig.CheckKeyIdOrFingerprint(e.PrimaryKey) {
			ident := e.PrimaryIdentity()
			return &openpgp.Key{
				Entity:        e,
				PublicKey:     e.PrimaryKey,
				SelfSignature: ident.SelfSignature,
				Revocations:   e.Revocations,
			}
		}

		for _, subKey := range e.Subkeys {
			if sig.CheckKeyIdOrFingerprint(subKey.PublicKey) {
				return &openpgp.Key{
					Entity:        e,
					PublicKey:     subKey.PublicKey,
					SelfSignature: subKey.Sig,
					Revocations:   subKey.Revocations,
				}
			}
		}
	}
	return nil
}
