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

package pkcs

// Verify PKCS#7 SignedData structures.

import (
	"io/ioutil"
	"os"

	"github.com/sassoftware/relic/v7/lib/magic"
	"github.com/sassoftware/relic/v7/lib/pkcs7"
	"github.com/sassoftware/relic/v7/lib/pkcs9"
	"github.com/sassoftware/relic/v7/lib/x509tools"
	"github.com/sassoftware/relic/v7/signers"
)

var PkcsSigner = &signers.Signer{
	Name:      "pkcs7",
	Magic:     magic.FileTypePKCS7,
	CertTypes: signers.CertTypeX509,
	Sign:      nil,
	Verify:    Verify,
}

func init() {
	PkcsSigner.Flags().String("content", "", "Specify file containing contents for detached signatures")
	signers.Register(PkcsSigner)
}

func Verify(f *os.File, opts signers.VerifyOpts) ([]*signers.Signature, error) {
	blob, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}
	psd, err := pkcs7.Unmarshal(blob)
	if err != nil {
		return nil, err
	}
	var cblob []byte
	if !opts.NoDigests && opts.Content != "" {
		cblob, err = ioutil.ReadFile(opts.Content)
		if err != nil {
			return nil, err
		}
	}
	sig, err := psd.Content.Verify(cblob, opts.NoDigests)
	if err != nil {
		return nil, err
	}
	ts, err := pkcs9.VerifyOptionalTimestamp(sig)
	if err != nil {
		return nil, err
	}
	hash, _ := x509tools.PkixDigestToHash(ts.SignerInfo.DigestAlgorithm)
	return []*signers.Signature{&signers.Signature{
		Hash:          hash,
		X509Signature: &ts,
	}}, nil
}
