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

package deb

// Sign Debian packages

import (
	"fmt"
	"io"
	"os"

	"github.com/sassoftware/relic/lib/audit"
	"github.com/sassoftware/relic/lib/certloader"
	"github.com/sassoftware/relic/lib/magic"
	"github.com/sassoftware/relic/lib/pgptools"
	"github.com/sassoftware/relic/lib/signdeb"
	"github.com/sassoftware/relic/signers"
	"github.com/sassoftware/relic/signers/sigerrors"
)

var DebSigner = &signers.Signer{
	Name:      "deb",
	Magic:     magic.FileTypeDEB,
	CertTypes: signers.CertTypePgp,
	FormatLog: formatLog,
	Sign:      sign,
	Verify:    verify,
}

func init() {
	DebSigner.Flags().StringP("role", "r", "builder", "(DEB) signing role: builder, origin, maint, archive")
	signers.Register(DebSigner)
}

func formatLog(attrs *audit.Info) string {
	return fmt.Sprintf("name=%s version=%s arch=%s",
		attrs.Attributes["deb.name"],
		attrs.Attributes["deb.version"],
		attrs.Attributes["deb.arch"],
	)
}

func sign(r io.Reader, cert *certloader.Certificate, opts signers.SignOpts) ([]byte, error) {
	role, _ := opts.Flags.GetString("role")
	if role == "" {
		role = "builder"
	}
	sig, err := signdeb.Sign(r, cert.PgpKey, opts.Hash, role)
	if err != nil {
		return nil, err
	}
	opts.Audit.Attributes["deb.name"] = sig.Info.Package
	opts.Audit.Attributes["deb.version"] = sig.Info.Version
	opts.Audit.Attributes["deb.arch"] = sig.Info.Arch
	return opts.SetBinPatch(sig.PatchSet)
}

func verify(f *os.File, opts signers.VerifyOpts) ([]*signers.Signature, error) {
	sigmap, err := signdeb.Verify(f, opts.TrustedPgp, opts.NoDigests)
	if _, ok := err.(pgptools.ErrNoKey); ok {
		return nil, fmt.Errorf("%s; use --cert to specify known keys", err)
	} else if err != nil {
		return nil, err
	}
	if len(sigmap) == 0 {
		return nil, sigerrors.NotSignedError{Type: "DEB"}
	}
	var ret []*signers.Signature
	for role, sig := range sigmap {
		rsig := &signers.Signature{
			SigInfo:      role,
			CreationTime: sig.CreationTime,
			Hash:         sig.Hash,
		}
		rsig.SignerPgp = sig.Key.Entity
		ret = append(ret, rsig)
	}
	return ret, nil
}
