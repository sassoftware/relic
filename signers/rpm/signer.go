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

package rpm

// Sign RedHat packages

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
	rpmutils "github.com/sassoftware/go-rpmutils"

	"github.com/sassoftware/relic/v7/lib/audit"
	"github.com/sassoftware/relic/v7/lib/binpatch"
	"github.com/sassoftware/relic/v7/lib/certloader"
	"github.com/sassoftware/relic/v7/lib/magic"
	"github.com/sassoftware/relic/v7/lib/pgptools"
	"github.com/sassoftware/relic/v7/signers"
	"github.com/sassoftware/relic/v7/signers/sigerrors"
)

var RpmSigner = &signers.Signer{
	Name:      "rpm",
	Magic:     magic.FileTypeRPM,
	CertTypes: signers.CertTypePgp,
	FormatLog: formatLog,
	Sign:      sign,
	Verify:    verify,
}

func init() {
	signers.Register(RpmSigner)
}

func formatLog(attrs *audit.Info) *zerolog.Event {
	return attrs.AttrsForLog("rpm.")
}

func sign(r io.Reader, cert *certloader.Certificate, opts signers.SignOpts) ([]byte, error) {
	config := &rpmutils.SignatureOptions{
		Hash:         opts.Hash,
		CreationTime: opts.Time.UTC().Round(time.Second),
	}
	header, err := rpmutils.SignRpmStream(r, cert.PgpKey.PrivateKey, config)
	if err != nil {
		return nil, err
	}
	blob, err := header.DumpSignatureHeader(true)
	if err != nil {
		return nil, err
	}
	patch := binpatch.New()
	patch.Add(0, int64(header.OriginalSignatureHeaderSize()), blob)
	md5, _ := header.GetBytes(rpmutils.SIG_MD5)
	sha1, _ := header.GetString(rpmutils.SIG_SHA1)
	opts.Audit.Attributes["rpm.nevra"] = nevra(header)
	opts.Audit.Attributes["rpm.md5"] = hex.EncodeToString(md5)
	opts.Audit.Attributes["rpm.sha1"] = sha1
	return opts.SetBinPatch(patch)
}

func verify(f *os.File, opts signers.VerifyOpts) ([]*signers.Signature, error) {
	// TODO: add a flag to skip payload digest to rpmutils.Verify
	header, sigs, err := rpmutils.Verify(f, opts.TrustedPgp)
	if err != nil {
		return nil, err
	}
	if len(sigs) == 0 {
		return nil, sigerrors.NotSignedError{Type: "RPM"}
	}
	var ret []*signers.Signature
	seen := make(map[uint64]bool)
	for _, sig := range sigs {
		if seen[sig.KeyId] {
			continue
		}
		seen[sig.KeyId] = true
		rsig := &signers.Signature{
			Package:      nevra(header),
			CreationTime: sig.CreationTime,
			Hash:         sig.Hash,
		}
		if sig.Signer == nil {
			if !opts.NoChain {
				return nil, pgptools.ErrNoKey(sig.KeyId)
			}
			rsig.Signer = fmt.Sprintf("UNKNOWN(%x)", sig.KeyId)
		} else {
			rsig.SignerPgp = sig.Signer
		}
		ret = append(ret, rsig)
	}
	return ret, nil
}

func nevra(header *rpmutils.RpmHeader) string {
	nevra, _ := header.GetNEVRA()
	snevra := nevra.String()
	// strip .rpm
	snevra = snevra[:len(snevra)-4]
	// strip zero epoch
	snevra = strings.ReplaceAll(snevra, "-0:", "-")
	return snevra
}
