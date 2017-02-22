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

package signrpm

import (
	"crypto"
	"io"
	"time"

	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/binpatch"
	"github.com/sassoftware/go-rpmutils"
	"golang.org/x/crypto/openpgp/packet"
)

func defaultOpts(opts *rpmutils.SignatureOptions) *rpmutils.SignatureOptions {
	var newOpts rpmutils.SignatureOptions
	if opts != nil {
		newOpts = *opts
	}
	if newOpts.Hash == 0 {
		newOpts.Hash = crypto.SHA256
	}
	if newOpts.CreationTime.IsZero() {
		newOpts.CreationTime = time.Now().UTC().Round(time.Second)
	}
	return &newOpts
}

func Sign(stream io.Reader, key *packet.PrivateKey, opts *rpmutils.SignatureOptions) (*binpatch.PatchSet, error) {
	opts = defaultOpts(opts)
	header, err := rpmutils.SignRpmStream(stream, key, opts)
	if err != nil {
		return nil, err
	}
	blob, err := header.DumpSignatureHeader(true)
	if err != nil {
		return nil, err
	}
	patch := binpatch.New(map[string]interface{}{
		"fingerprint": key.Fingerprint,
		"timestamp":   opts.CreationTime.String(),
	})
	patch.Add(0, uint32(header.OriginalSignatureHeaderSize()), blob)
	return patch, nil
}
