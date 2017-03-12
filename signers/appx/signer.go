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

package appx

// Sign Windows Universal (UWP) .appx and .appxbundle

import (
	"fmt"
	"io"
	"os"
	"path"

	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/signappx"
	"gerrit-pdt.unx.sas.com/tools/relic.git/signers"
)

var AppxSigner = &signers.Signer{
	Name:      "appx",
	CertTypes: signers.CertTypeX509,
	TestPath:  testPath,
	Verify:    verify,
}

func init() {
	signers.Register(AppxSigner)
}

func testPath(filepath string) bool {
	ext := path.Ext(filepath)
	return ext == ".appx" || ext == ".appxbundle"
}

func verify(f *os.File, opts signers.VerifyOpts) ([]*signers.Signature, error) {
	size, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		return nil, err
	}
	sig, err := signappx.Verify(f, size, opts.NoDigests)
	if err != nil {
		return nil, err
	}
	appxSig := sig
	if sig.IsBundle {
		for _, nested := range sig.Bundled {
			appxSig = nested
			break
		}
	}
	return []*signers.Signature{&signers.Signature{
		Package:       fmt.Sprintf("{%s} %s %s", appxSig.Name, appxSig.DisplayName, appxSig.Version),
		Hash:          sig.Hash,
		X509Signature: sig.Signature,
	}}, nil
	return nil, nil
}
