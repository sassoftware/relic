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

	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/pgptools"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/signdeb"
)

func verifyDeb(f *os.File) error {
	sigmap, err := signdeb.Verify(f, trustedPgp, argNoIntegrityCheck)
	if _, ok := err.(pgptools.ErrNoKey); ok {
		return fmt.Errorf("%s; use --cert to specify trusted keys", err)
	} else if err != nil {
		return err
	}
	if len(sigmap) == 0 {
		return errors.New("DEB is not signed")
	}
	for role, sig := range sigmap {
		showPgp(sig, fmt.Sprintf("%s(%s)", f.Name(), role), nil)
	}
	return nil
}
