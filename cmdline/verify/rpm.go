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
	"errors"
	"fmt"
	"os"

	"github.com/sassoftware/go-rpmutils"
)

func verifyRpm(f *os.File) error {
	trusted := trustedPgp
	if argNoChain {
		trusted = nil
	} else if len(trusted) == 0 {
		return errors.New("Need one or more PGP keys to validate against; use --cert or --no-trust-chain")
	}
	_, sigs, err := rpmutils.Verify(f, trustedPgp)
	if err != nil {
		return err
	}
	if len(sigs) == 0 {
		return errors.New("RPM is not signed")
	}
	seen := make(map[uint64]bool)
	for _, sig := range sigs {
		var name string
		if seen[sig.KeyId] {
			continue
		}
		seen[sig.KeyId] = true
		if sig.Signer != nil {
			var firstName string
			for _, ident := range sig.Signer.Identities {
				if firstName == "" {
					firstName = ident.Name
				}
				if ident.SelfSignature.IsPrimaryId != nil && *ident.SelfSignature.IsPrimaryId {
					name = ident.Name
					break
				}
			}
			if name == "" {
				name = firstName
			}
		}
		fmt.Printf("%s: OK - %s(%x) [%s]\n", f.Name(), name, sig.KeyId, sig.CreationTime)
	}
	return nil
}
