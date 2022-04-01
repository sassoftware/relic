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

package jar

// Sign Java archives

import (
	"archive/zip"
	"io"
	"os"

	"github.com/sassoftware/relic/v7/lib/certloader"
	"github.com/sassoftware/relic/v7/lib/magic"
	"github.com/sassoftware/relic/v7/lib/signjar"
	"github.com/sassoftware/relic/v7/signers"
	"github.com/sassoftware/relic/v7/signers/zipbased"
)

var JarSigner = &signers.Signer{
	Name:      "jar",
	Magic:     magic.FileTypeJAR,
	CertTypes: signers.CertTypeX509,
	Transform: zipbased.Transform,
	Sign:      sign,
	Verify:    verify,
}

func init() {
	JarSigner.Flags().Bool("sections-only", false, "(JAR) Don't compute hash of entire manifest")
	JarSigner.Flags().Bool("inline-signature", false, "(JAR) Include .SF inside the signature block")
	JarSigner.Flags().Bool("apk-v2-present", false, "(JAR) Add X-Android-APK-Signed header to signature")
	JarSigner.Flags().String("key-alias", "RELIC", "(JAR, APK) Alias to use for the signed manifest")
	signers.Register(JarSigner)
}

// sign a manifest and return the PKCS#7 blob
func sign(r io.Reader, cert *certloader.Certificate, opts signers.SignOpts) ([]byte, error) {
	argSectionsOnly := opts.Flags.GetBool("sections-only")
	argInlineSignature := opts.Flags.GetBool("inline-signature")
	argApkV2 := opts.Flags.GetBool("apk-v2-present")
	argAlias := opts.Flags.GetString("key-alias")
	if argAlias == "" {
		argAlias = "RELIC"
	}
	digest, err := signjar.DigestJarStream(r, opts.Hash)
	if err != nil {
		return nil, err
	}
	patch, ts, err := digest.Sign(opts.Context(), cert, argAlias, argSectionsOnly, argInlineSignature, argApkV2)
	if err != nil {
		return nil, err
	}
	opts.Audit.SetCounterSignature(ts.CounterSignature)
	return opts.SetBinPatch(patch)
}

func verify(f *os.File, opts signers.VerifyOpts) ([]*signers.Signature, error) {
	inz, err := openZip(f)
	if err != nil {
		return nil, err
	}
	sigs, err := signjar.Verify(inz, opts.NoDigests)
	if err != nil {
		return nil, err
	}
	var ret []*signers.Signature
	for _, ts := range sigs {
		ret = append(ret, &signers.Signature{
			Hash:          ts.Hash,
			X509Signature: &ts.TimestampedSignature,
		})
	}
	return ret, nil
}

func openZip(f *os.File) (*zip.Reader, error) {
	size, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		return nil, err
	}
	if _, err := f.Seek(0, 0); err != nil {
		return nil, err
	}
	return zip.NewReader(f, size)
}
