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

package signappx

import (
	"crypto/hmac"
	"errors"
	"fmt"
	"io"

	"github.com/sassoftware/relic/v7/lib/zipslicer"
)

func verifyMeta(r io.ReaderAt, size int64, sig *AppxSignature, skipDigests bool) error {
	dir, err := zipslicer.Read(r, size)
	if err != nil {
		return err
	}
	sigIdx := -1
	for i, f := range dir.File {
		if f.Name == appxSignature {
			sigIdx = i
		} else if sigIdx >= 0 {
			return errors.New("zip elements out of order")
		}
	}

	// AXPC is a hash of everything except the central directory and signature file
	axpc := sig.Hash.New()
	sink := io.Writer(axpc)
	if skipDigests {
		sink = nil
	}
	// AXCD is a hash of the zip central directory with the signature file removed
	axcd := sig.Hash.New()
	if err := dir.Truncate(sigIdx, sink, axcd); err != nil {
		return fmt.Errorf("verifying zip metadata: %w", err)
	}
	if !skipDigests {
		calc := axpc.Sum(nil)
		if expected := sig.HashValues["AXPC"]; !hmac.Equal(calc, expected) {
			return fmt.Errorf("appx digest mismatch for zip contents: calculated %x != found %x", calc, expected)
		}
	}
	calc := axcd.Sum(nil)
	if expected := sig.HashValues["AXCD"]; !hmac.Equal(calc, expected) {
		return fmt.Errorf("appx digest mismatch for zip directory: calculated %x != found %x", calc, expected)
	}
	return nil
}
