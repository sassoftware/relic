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

package msi

// Sign Microsoft Installer files

import (
	"io"
	"io/ioutil"
	"os"

	"github.com/sassoftware/relic/v7/lib/atomicfile"
	"github.com/sassoftware/relic/v7/lib/authenticode"
	"github.com/sassoftware/relic/v7/lib/certloader"
	"github.com/sassoftware/relic/v7/lib/comdoc"
	"github.com/sassoftware/relic/v7/lib/magic"
	"github.com/sassoftware/relic/v7/signers"
	"github.com/sassoftware/relic/v7/signers/pecoff"
)

var MsiSigner = &signers.Signer{
	Name:      "msi",
	Aliases:   []string{"msi-tar"},
	Magic:     magic.FileTypeMSI,
	CertTypes: signers.CertTypeX509,
	Transform: transform,
	Sign:      sign,
	Verify:    verify,
}

func init() {
	MsiSigner.Flags().Bool("no-extended-sig", false, "(MSI) Don't emit a MsiDigitalSignatureEx digest")
	pecoff.AddOpusFlags(MsiSigner)
	signers.Register(MsiSigner)
}

type msiTransformer struct {
	f     *os.File
	cdf   *comdoc.ComDoc
	exsig []byte
}

func transform(f *os.File, opts signers.SignOpts) (signers.Transformer, error) {
	cdf, err := comdoc.ReadFile(f)
	if err != nil {
		return nil, err
	}
	var exsig []byte
	noExtended := opts.Flags.GetBool("no-extended-sig")
	if !noExtended {
		exsig, err = authenticode.PrehashMSI(cdf, opts.Hash)
		if err != nil {
			return nil, err
		}
	}
	return &msiTransformer{f, cdf, exsig}, nil
}

// transform the MSI to a tar stream for upload
func (t *msiTransformer) GetReader() (io.Reader, error) {
	r, w := io.Pipe()
	go func() {
		_ = w.CloseWithError(authenticode.MsiToTar(t.cdf, w))
	}()
	return r, nil
}

// apply a signed PKCS#7 blob to an already-open MSI document
func (t *msiTransformer) Apply(dest, mimeType string, result io.Reader) error {
	t.cdf.Close()
	blob, err := ioutil.ReadAll(result)
	if err != nil {
		return err
	}
	// copy src to dest if needed, otherwise open in-place
	f, err := atomicfile.WriteInPlace(t.f, dest)
	if err != nil {
		return err
	}
	defer f.Close()
	cdf, err := comdoc.WriteFile(f.GetFile())
	if err != nil {
		return err
	}
	if err := authenticode.InsertMSISignature(cdf, blob, t.exsig); err != nil {
		return err
	}
	if err := cdf.Close(); err != nil {
		return err
	}
	return f.Commit()
}

// sign a transformed tarball and return the PKCS#7 blob
func sign(r io.Reader, cert *certloader.Certificate, opts signers.SignOpts) ([]byte, error) {
	noExtended := opts.Flags.GetBool("no-extended-sig")
	sum, err := authenticode.DigestMsiTar(r, opts.Hash, !noExtended)
	if err != nil {
		return nil, err
	}
	ts, err := authenticode.SignMSIImprint(opts.Context(), sum, opts.Hash, cert, pecoff.OpusFlags(opts))
	if err != nil {
		return nil, err
	}
	return opts.SetPkcs7(ts)
}

func verify(f *os.File, opts signers.VerifyOpts) ([]*signers.Signature, error) {
	sig, err := authenticode.VerifyMSI(f, opts.NoDigests)
	if err != nil {
		return nil, err
	}
	return []*signers.Signature{{
		Hash:          sig.HashFunc,
		X509Signature: &sig.TimestampedSignature,
		SigInfo:       pecoff.FormatOpus(sig.OpusInfo),
	}}, nil
}
