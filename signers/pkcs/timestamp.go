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

package pkcs

// Verify PKCS#7 SignedData structures. Also includes shared code for
// serializing other signature types that use PKCS#7.

import (
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"gerrit-pdt.unx.sas.com/tools/relic.git/config"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/certloader"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/magic"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/pkcs7"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/pkcs9"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/x509tools"
	"gerrit-pdt.unx.sas.com/tools/relic.git/signers"
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

func Timestamp(psd *pkcs7.ContentInfoSignedData, cert *certloader.Certificate, opts signers.SignOpts, authenticode bool) (sig []byte, err error) {
	tconf := opts.TimestampConfig
	if tconf != nil {
		signerInfo := &psd.Content.SignerInfos[0]
		d := opts.Hash.New()
		d.Write(signerInfo.EncryptedDigest)
		imprint := d.Sum(nil)

		cl := pkcs9.TimestampClient{
			UserAgent: config.UserAgent,
			CaFile:    tconf.CaCert,
			Timeout:   time.Second * time.Duration(tconf.Timeout),
		}
		var token *pkcs7.ContentInfoSignedData
		for _, url := range tconf.Urls {
			cl.Url = url
			if err != nil {
				fmt.Fprintf(os.Stderr, "Timestamping failed: %s\nTrying next server %s...\n", err, cl.Url)
			}
			token, err = cl.Request(opts.Hash, imprint)
			if err == nil {
				break
			}
		}
		if err != nil {
			return nil, fmt.Errorf("Timestamping failed: %s", err)
		}
		if authenticode {
			err = pkcs9.AddStampToSignedAuthenticode(signerInfo, *token)
		} else {
			err = pkcs9.AddStampToSignedData(signerInfo, *token)
		}
	}
	verified, err := psd.Content.Verify(nil, false)
	if err != nil {
		return nil, fmt.Errorf("pkcs7: failed signature self-check: %s", err)
	}
	ts, err := pkcs9.VerifyOptionalTimestamp(verified)
	if err != nil {
		return nil, fmt.Errorf("pkcs7: failed signature self-check: %s", err)
	}
	opts.Audit.SetCounterSignature(ts.CounterSignature)
	opts.Audit.SetMimeType(pkcs7.MimeType)
	return psd.Marshal()
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
