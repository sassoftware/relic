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

package ps

// Sign Microsoft PowerShell scripts, modules, and other bits that can be signed

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/sassoftware/relic/v7/lib/authenticode"
	"github.com/sassoftware/relic/v7/lib/certloader"
	"github.com/sassoftware/relic/v7/lib/x509tools"
	"github.com/sassoftware/relic/v7/signers"
	"github.com/sassoftware/relic/v7/signers/pecoff"
)

var PsSigner = &signers.Signer{
	Name:      "ps",
	CertTypes: signers.CertTypeX509,
	TestPath:  testPath,
	Transform: transform,
	Sign:      sign,
	Verify:    verify,
}

func init() {
	PsSigner.Flags().String("ps-style", "", "(Powershell) signature type")
	pecoff.AddOpusFlags(PsSigner)
	signers.Register(PsSigner)
}

func testPath(fp string) bool {
	_, ok := authenticode.GetSigStyle(fp)
	return ok
}

func transform(f *os.File, opts signers.SignOpts) (signers.Transformer, error) {
	// detect signature style and explicitly set it for the request
	argStyle := opts.Flags.GetString("ps-style")
	if argStyle == "" {
		argStyle = filepath.Ext(opts.Path)
	}
	opts.Flags.Values["ps-style"] = argStyle
	return signers.DefaultTransform(f), nil
}

func sign(r io.Reader, cert *certloader.Certificate, opts signers.SignOpts) ([]byte, error) {
	argStyle := opts.Flags.GetString("ps-style")
	if argStyle == "" {
		argStyle = opts.Path
	}
	style, err := getStyle(argStyle)
	if err != nil {
		return nil, err
	}
	digest, err := authenticode.DigestPowershell(r, style, opts.Hash)
	if err != nil {
		return nil, err
	}
	patch, ts, err := digest.Sign(opts.Context(), cert, pecoff.OpusFlags(opts))
	if err != nil {
		return nil, err
	}
	opts.Audit.SetCounterSignature(ts.CounterSignature)
	return opts.SetBinPatch(patch)
}

func verify(f *os.File, opts signers.VerifyOpts) ([]*signers.Signature, error) {
	style, err := getStyle(f.Name())
	if err != nil {
		return nil, err
	}
	ts, err := authenticode.VerifyPowershell(f, style, opts.NoDigests)
	if err != nil {
		return nil, err
	}
	hash, _ := x509tools.PkixDigestToHash(ts.SignerInfo.DigestAlgorithm)
	return []*signers.Signature{{
		Hash:          hash,
		X509Signature: &ts.TimestampedSignature,
		SigInfo:       pecoff.FormatOpus(ts.OpusInfo),
	}}, nil
}

func getStyle(name string) (authenticode.PsSigStyle, error) {
	style, ok := authenticode.GetSigStyle(name)
	if !ok {
		return 0, errors.New("unknown powershell style, expected: " + strings.Join(authenticode.AllSigStyles(), " "))
	}
	return style, nil
}
