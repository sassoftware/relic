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
	"fmt"
	"io"
	"os"

	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/pgptools"
	"golang.org/x/crypto/openpgp/armor"
)

func verifyPgp(f *os.File) error {
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
			sig, _, err := pgptools.VerifyClearSign(f, trustedPgp)
			return showPgp(sig, f.Name(), err)
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
		sig, err := pgptools.VerifyDetached(reader, fc, trustedPgp)
		return showPgp(sig, f.Name(), err)
	} else {
		// inline signature
		sig, _, err := pgptools.VerifyInline(reader, trustedPgp)
		return showPgp(sig, f.Name(), err)
	}
}

func showPgp(sig *pgptools.PgpSignature, name string, err error) error {
	if err == nil {
		fmt.Printf("%s: OK - %s(%x) [%s]\n", name, pgptools.EntityName(sig.Key.Entity), sig.Key.PublicKey.KeyId, sig.CreationTime)
		return nil
	} else if sig != nil {
		return fmt.Errorf("bad signature from %s(%x) [%s]: %s\n", pgptools.EntityName(sig.Key.Entity), sig.Key.PublicKey.KeyId, sig.CreationTime, err)
	} else if _, ok := err.(pgptools.ErrNoKey); ok {
		return fmt.Errorf("%s; use --cert to specify trusted keys", err)
	} else {
		return err
	}
}
