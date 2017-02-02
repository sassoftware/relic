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

package pkcs9

import (
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/pkcs7"
)

func AddStampToSignedData(signerInfo *pkcs7.SignerInfo, token pkcs7.ContentInfoSignedData) error {
	return signerInfo.UnauthenticatedAttributes.Add(OidAttributeTimeStampToken, token)
}

// Validated timestamp token
type CounterSignature struct {
	pkcs7.Signature
	SigningTime time.Time
}

// Validated signature containing a valid timestamp token
type TimestampedSignature struct {
	pkcs7.Signature
	CounterSignature *CounterSignature
}

// Look for a timestamp (counter-signature or timestamp token) in the
// UnauthenticatedAttributes of the given already-validated signature and check
// its integrity. The certificate chain is not checked; call VerifyChain() on
// the result to validate it fully.
func VerifyTimestamp(sig pkcs7.Signature) (CounterSignature, error) {
	var tst pkcs7.ContentInfoSignedData
	var tsi pkcs7.SignerInfo
	// check several OIDs for timestamp tokens
	err := sig.SignerInfo.UnauthenticatedAttributes.GetOne(OidAttributeTimeStampToken, &tst)
	if _, ok := err.(pkcs7.ErrNoAttribute); ok {
		err = sig.SignerInfo.UnauthenticatedAttributes.GetOne(OidSpcTimeStampToken, &tst)
	}
	var verifyBlob []byte
	certs := sig.Intermediates
	if err == nil {
		// timestamptoken is a fully nested signedData
		if len(tst.Content.SignerInfos) != 1 {
			return CounterSignature{}, errors.New("counter-signature should have exactly one SignerInfo")
		}
		tsi = tst.Content.SignerInfos[0]
		tsicerts, err := tst.Content.Certificates.Parse()
		if err != nil {
			return CounterSignature{}, err
		} else if len(tsicerts) != 0 {
			// keep both sets of certs just in case
			certs = append(certs, tsicerts...)
		}
		verifyBlob, err = tst.Content.ContentInfo.Bytes()
		if err != nil {
			return CounterSignature{}, err
		}
	} else if _, ok := err.(pkcs7.ErrNoAttribute); ok {
		if err := sig.SignerInfo.UnauthenticatedAttributes.GetOne(OidAttributeCounterSign, &tsi); err != nil {
			return CounterSignature{}, err
		}
		// counterSignature is just a signerinfo and the certificates come from
		// the parent signedData
		verifyBlob = sig.SignerInfo.EncryptedDigest
	} else {
		return CounterSignature{}, err
	}
	cert, err := tsi.Verify(verifyBlob, false, certs)
	if err != nil {
		return CounterSignature{}, err
	}
	var signingTime time.Time
	if err := tsi.AuthenticatedAttributes.GetOne(pkcs7.OidAttributeSigningTime, &signingTime); err != nil {
		return CounterSignature{}, err
	}
	return CounterSignature{
		Signature: pkcs7.Signature{
			SignerInfo:    &tsi,
			Certificate:   cert,
			Intermediates: certs,
		},
		SigningTime: signingTime,
	}, nil
}

// Look for a timestamp token or counter-signature in the given signature and
// return a structure that can be used to validate the signature's certificate
// chain. If no timestamp is present, then the current time will be used when
// validating the chain.
func VerifyOptionalTimestamp(sig pkcs7.Signature) (TimestampedSignature, error) {
	tsig := TimestampedSignature{Signature: sig}
	ts, err := VerifyTimestamp(sig)
	if _, ok := err.(pkcs7.ErrNoAttribute); ok {
		return tsig, nil
	} else if err != nil {
		return tsig, err
	} else {
		tsig.CounterSignature = &ts
		return tsig, nil
	}
}

// Verify that the timestamp token has a valid certificate chain
func (cs CounterSignature) VerifyChain(roots *x509.CertPool, extraCerts []*x509.Certificate) error {
	pool := x509.NewCertPool()
	for _, cert := range extraCerts {
		pool.AddCert(cert)
	}
	for _, cert := range cs.Intermediates {
		pool.AddCert(cert)
	}
	opts := x509.VerifyOptions{
		Intermediates: pool,
		Roots:         roots,
		CurrentTime:   cs.SigningTime,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	}
	_, err := cs.Certificate.Verify(opts)
	return err
}

func (sig TimestampedSignature) VerifyChain(roots *x509.CertPool, extraCerts []*x509.Certificate, usage x509.ExtKeyUsage) error {
	var signingTime time.Time
	if sig.CounterSignature != nil {
		if err := sig.CounterSignature.VerifyChain(roots, extraCerts); err != nil {
			return fmt.Errorf("validating timestamp: %s", err)
		}
		signingTime = sig.CounterSignature.SigningTime
	}
	return sig.Signature.VerifyChain(roots, extraCerts, usage, signingTime)
}
