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

package pecoff

// Sign Microsoft PE/COFF executables

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/sassoftware/relic/v7/lib/authenticode"
	"github.com/sassoftware/relic/v7/lib/certloader"
	"github.com/sassoftware/relic/v7/lib/magic"
	"github.com/sassoftware/relic/v7/signers"
)

var PeSigner = &signers.Signer{
	Name:      "pe-coff",
	Magic:     magic.FileTypePECOFF,
	CertTypes: signers.CertTypeX509,
	Sign:      sign,
	Fixup:     authenticode.FixPEChecksum,
	Verify:    verify,
}

func init() {
	PeSigner.Flags().Bool("page-hashes", false, "(PE-COFF) Add page hashes to signature")
	AddOpusFlags(PeSigner)
	signers.Register(PeSigner)
}

func AddOpusFlags(s *signers.Signer) {
	s.Flags().String("description", "", "(Win) Set description of signed content")
	s.Flags().String("desc-url", "", "(Win) Set URL for description of signed content")
}

func OpusFlags(opts signers.SignOpts) *authenticode.OpusParams {
	return &authenticode.OpusParams{
		Description: opts.Flags.GetString("description"),
		URL:         opts.Flags.GetString("desc-url"),
	}
}

func sign(r io.Reader, cert *certloader.Certificate, opts signers.SignOpts) ([]byte, error) {
	pageHashes := opts.Flags.GetBool("page-hashes")
	digest, err := authenticode.DigestPE(r, opts.Hash, pageHashes)
	if err != nil {
		return nil, err
	}
	patch, ts, err := digest.Sign(opts.Context(), cert, OpusFlags(opts))
	if err != nil {
		return nil, err
	}
	opts.Audit.Attributes["pe-coff.pagehashes"] = pageHashes
	opts.Audit.SetCounterSignature(ts.CounterSignature)
	return opts.SetBinPatch(patch)
}

func FormatOpus(info *authenticode.SpcSpOpusInfo) string {
	if info == nil {
		return ""
	}
	var infos []string
	if desc := info.ProgramName.String(); desc != "" {
		infos = append(infos, fmt.Sprintf("[desc:%q]", desc))
	}
	if u := info.MoreInfo.URL; u != "" {
		infos = append(infos, fmt.Sprintf("[url:%q]", u))
	}
	return strings.Join(infos, "")
}

func verify(f *os.File, opts signers.VerifyOpts) ([]*signers.Signature, error) {
	sigs, err := authenticode.VerifyPE(f, opts.NoDigests)
	if err != nil {
		return nil, err
	}
	var ret []*signers.Signature
	for _, sig := range sigs {
		ret = append(ret, &signers.Signature{
			SigInfo:       FormatOpus(sig.OpusInfo),
			Hash:          sig.ImageHashFunc,
			X509Signature: &sig.TimestampedSignature,
		})
	}
	return ret, nil
}
