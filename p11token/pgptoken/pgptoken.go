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

package pgptoken

import (
	"bytes"
	"errors"
	"io"
	"io/ioutil"

	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/x509tools"
	"gerrit-pdt.unx.sas.com/tools/relic.git/p11token"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
)

func readEntity(path string) (*openpgp.Entity, error) {
	blob, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var reader io.Reader = bytes.NewReader(blob)
	if blob[0] == '-' {
		block, err := armor.Decode(reader)
		if err != nil {
			return nil, err
		}
		reader = block.Body
	}
	return openpgp.ReadEntity(packet.NewReader(reader))
}

func KeyFromToken(key *p11token.Key) (*openpgp.Entity, error) {
	if key.Certificate == "" {
		return nil, errors.New("'certificate' setting in key configuration must point to a PGP public key file")
	}
	entity, err := readEntity(key.Certificate)
	if err != nil {
		return nil, err
	}
	priv := &packet.PrivateKey{
		PublicKey:  *entity.PrimaryKey,
		Encrypted:  false,
		PrivateKey: key,
	}
	if !x509tools.SameKey(key.Public(), priv.PublicKey.PublicKey) {
		return nil, errors.New("Certificate does not match specified key in token")
	}
	entity.PrivateKey = priv
	return entity, nil
}
