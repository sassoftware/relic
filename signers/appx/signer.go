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

package appx

// Sign Windows Universal (UWP) .appx and .appxbundle

import (
	"fmt"
	"io"
	"os"

	"github.com/sassoftware/relic/lib/certloader"
	"github.com/sassoftware/relic/lib/magic"
	"github.com/sassoftware/relic/lib/signappx"
	"github.com/sassoftware/relic/signers"
	"github.com/sassoftware/relic/signers/zipbased"
)

var AppxSigner = &signers.Signer{
	Name:      "appx",
	Magic:     magic.FileTypeAPPX,
	CertTypes: signers.CertTypeX509,
	Transform: zipbased.Transform,
	Sign:      sign,
	Verify:    verify,
}

func init() {
	signers.Register(AppxSigner)
}

func sign(r io.Reader, cert *certloader.Certificate, opts signers.SignOpts) ([]byte, error) {
	digest, err := signappx.DigestAppxTar(r, opts.Hash, false)
	if err != nil {
		return nil, err
	}
	patch, priSig, _, err := digest.Sign(opts.Context(), cert)
	if err != nil {
		return nil, err
	}
	opts.Audit.SetCounterSignature(priSig.CounterSignature)
	return opts.SetBinPatch(patch)
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
}
