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

package cab

// Sign Microsoft cabinet files

import (
	"io"
	"os"

	"github.com/sassoftware/relic/v7/lib/authenticode"
	"github.com/sassoftware/relic/v7/lib/cabfile"
	"github.com/sassoftware/relic/v7/lib/certloader"
	"github.com/sassoftware/relic/v7/lib/magic"
	"github.com/sassoftware/relic/v7/signers"
	"github.com/sassoftware/relic/v7/signers/pecoff"
)

var CabSigner = &signers.Signer{
	Name:      "cab",
	Magic:     magic.FileTypeCAB,
	CertTypes: signers.CertTypeX509,
	Sign:      sign,
	Verify:    verify,
}

func init() {
	pecoff.AddOpusFlags(CabSigner)
	signers.Register(CabSigner)
}

func sign(r io.Reader, cert *certloader.Certificate, opts signers.SignOpts) ([]byte, error) {
	digest, err := cabfile.Digest(r, opts.Hash)
	if err != nil {
		return nil, err
	}
	patch, ts, err := authenticode.SignCabImprint(opts.Context(), digest, cert, pecoff.OpusFlags(opts))
	if err != nil {
		return nil, err
	}
	opts.Audit.SetCounterSignature(ts.CounterSignature)
	return opts.SetBinPatch(patch)
}

func verify(f *os.File, opts signers.VerifyOpts) ([]*signers.Signature, error) {
	sig, err := authenticode.VerifyCab(f, opts.NoDigests)
	if err != nil {
		return nil, err
	}
	return []*signers.Signature{{
		Hash:          sig.HashFunc,
		X509Signature: &sig.TimestampedSignature,
		SigInfo:       pecoff.FormatOpus(sig.OpusInfo),
	}}, nil
}
