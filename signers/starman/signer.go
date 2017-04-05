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

package starman

// tarball format used by SAS

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"

	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/binpatch"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/certloader"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/magic"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/pgptools"
	"gerrit-pdt.unx.sas.com/tools/relic.git/signers"
)

var Signer = &signers.Signer{
	Name:         "starman",
	Magic:        magic.FileTypeStarman,
	CertTypes:    signers.CertTypePgp,
	Sign:         sign,
	VerifyStream: verify,
}

func init() {
	signers.Register(Signer)
}

func sign(r io.Reader, cert *certloader.Certificate, opts signers.SignOpts) ([]byte, error) {
	info, err := verifyMeta(r)
	if err != nil {
		return nil, err
	}
	// sign metadata
	var sigbuf bytes.Buffer
	config := &packet.Config{
		DefaultHash: opts.Hash,
		Time:        func() time.Time { return opts.Time },
	}
	if err := openpgp.ArmoredDetachSign(&sigbuf, cert.PgpKey, bytes.NewReader(info.mdblob), config); err != nil {
		return nil, err
	}
	// preserve the existing padding size so an in-place patch can be done
	padding := len(info.sigblob) - sigbuf.Len()
	if padding > 0 {
		sigbuf.Write(make([]byte, padding))
	}
	// build a tar fragment to insert
	var twbuf bytes.Buffer
	tw := tar.NewWriter(&twbuf)
	tw.WriteHeader(&tar.Header{
		Name: info.mdname + sigSuffix,
		Mode: 0644,
		Size: int64(sigbuf.Len()),
	})
	tw.Write(sigbuf.Bytes())
	tw.Flush()
	// turn fragment into a binpatch
	patch := binpatch.New()
	patch.Add(info.sigStart, info.sigEnd-info.sigStart, twbuf.Bytes())
	opts.Audit.Attributes["rpm.name"] = info.md.Name
	opts.Audit.Attributes["rpm.epoch"] = info.md.Version.Epoch
	opts.Audit.Attributes["rpm.version"] = info.md.Version.Version
	opts.Audit.Attributes["rpm.release"] = info.md.Version.Release
	opts.Audit.Attributes["rpm.arch"] = info.md.Arch
	if epoch := info.md.Version.Epoch; epoch != "" && epoch != "0" {
		opts.Audit.Attributes["rpm.nevra"] = fmt.Sprintf("%s-%s:%s-%s.%s", info.md.Name, epoch, info.md.Version.Version, info.md.Version.Release, info.md.Arch)
	} else {
		opts.Audit.Attributes["rpm.nevra"] = fmt.Sprintf("%s-%s-%s.%s", info.md.Name, info.md.Version.Version, info.md.Version.Release, info.md.Arch)
	}
	return opts.SetBinPatch(patch)
}

func verify(r io.Reader, opts signers.VerifyOpts) ([]*signers.Signature, error) {
	info, err := verifyMeta(r)
	if err != nil {
		return nil, err
	}
	if !info.hasSig {
		return nil, errors.New("file is not signed")
	}
	block, err := armor.Decode(bytes.NewReader(info.sigblob))
	if err != nil {
		return nil, err
	}
	sig, err := pgptools.VerifyDetached(block.Body, bytes.NewReader(info.mdblob), opts.TrustedPgp)
	if err == nil {
		return []*signers.Signature{&signers.Signature{
			CreationTime: sig.CreationTime,
			Hash:         sig.Hash,
			SignerPgp:    sig.Key.Entity,
		}}, nil
	} else if sig != nil {
		return nil, fmt.Errorf("bad signature from %s(%x) [%s]: %s", pgptools.EntityName(sig.Key.Entity), sig.Key.PublicKey.KeyId, sig.CreationTime, err)
	} else if _, ok := err.(pgptools.ErrNoKey); ok {
		return nil, fmt.Errorf("%s; use --cert to specify known keys", err)
	}
	return nil, err
}
