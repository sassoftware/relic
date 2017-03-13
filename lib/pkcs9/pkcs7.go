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
	"bytes"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/pkcs7"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/x509tools"
)

type Timestamper interface {
	Timestamp(psd *pkcs7.ContentInfoSignedData) (token *pkcs7.ContentInfoSignedData, err error)
}

func TimestampAndMarshal(psd *pkcs7.ContentInfoSignedData, timestamper Timestamper, authenticode bool) (*TimestampedSignature, error) {
	if timestamper != nil {
		token, err := timestamper.Timestamp(psd)
		if err != nil {
			return nil, err
		}
		if token != nil {
			signerInfo := &psd.Content.SignerInfos[0]
			var err error
			if authenticode {
				err = AddStampToSignedAuthenticode(signerInfo, *token)
			} else {
				err = AddStampToSignedData(signerInfo, *token)
			}
			if err != nil {
				return nil, err
			}
		}
	}
	verified, err := psd.Content.Verify(nil, false)
	if err != nil {
		return nil, fmt.Errorf("pkcs7: failed signature self-check: %s", err)
	}
	ts, err := VerifyOptionalTimestamp(verified)
	if err != nil {
		return nil, fmt.Errorf("pkcs7: failed signature self-check: %s", err)
	}
	blob, err := psd.Marshal()
	if err != nil {
		return nil, err
	}
	ts.Raw = blob
	return &ts, err
}

// Attach a RFC 3161 timestamp to a PKCS#7 SignerInfo
func AddStampToSignedData(signerInfo *pkcs7.SignerInfo, token pkcs7.ContentInfoSignedData) error {
	return signerInfo.UnauthenticatedAttributes.Add(OidAttributeTimeStampToken, token)
}

// Attach a RFC 3161 timestamp to a PKCS#7 SignerInfo using the OID for authenticode signatures
func AddStampToSignedAuthenticode(signerInfo *pkcs7.SignerInfo, token pkcs7.ContentInfoSignedData) error {
	return signerInfo.UnauthenticatedAttributes.Add(OidSpcTimeStampToken, token)
}

// Validated timestamp token
type CounterSignature struct {
	pkcs7.Signature
	Hash        crypto.Hash
	SigningTime time.Time
}

// Validated signature containing a optional timestamp token
type TimestampedSignature struct {
	pkcs7.Signature
	CounterSignature *CounterSignature
	Raw              []byte
}

// Look for a timestamp (counter-signature or timestamp token) in the
// UnauthenticatedAttributes of the given already-validated signature and check
// its integrity. The certificate chain is not checked; call VerifyChain() on
// the result to validate it fully.
func VerifyTimestamp(sig pkcs7.Signature) (*CounterSignature, error) {
	var tst pkcs7.ContentInfoSignedData
	var tsi pkcs7.SignerInfo
	// check several OIDs for timestamp tokens
	err := sig.SignerInfo.UnauthenticatedAttributes.GetOne(OidAttributeTimeStampToken, &tst)
	if _, ok := err.(pkcs7.ErrNoAttribute); ok {
		err = sig.SignerInfo.UnauthenticatedAttributes.GetOne(OidSpcTimeStampToken, &tst)
	}
	var verifyBlob []byte
	var imprintHash crypto.Hash
	certs := sig.Intermediates
	if err == nil {
		// timestamptoken is a fully nested signedData containing a TSTInfo
		// that digests the parent signature blob
		if len(tst.Content.SignerInfos) != 1 {
			return nil, errors.New("timestamp should have exactly one SignerInfo")
		}
		tsi = tst.Content.SignerInfos[0]
		tsicerts, err := tst.Content.Certificates.Parse()
		if err != nil {
			return nil, err
		} else if len(tsicerts) != 0 {
			// keep both sets of certs just in case
			certs = append(certs, tsicerts...)
		}
		// verify the imprint in the TSTInfo
		if tstinfo, err := UnpackTokenInfo(&tst); err != nil {
			return nil, err
		} else if verr := tstinfo.MessageImprint.Verify(sig.SignerInfo.EncryptedDigest); verr != nil {
			return nil, fmt.Errorf("failed to verify timestamp imprint: %s", verr)
		} else {
			imprintHash, _ = x509tools.PkixDigestToHash(tstinfo.MessageImprint.HashAlgorithm)
		}
		// now the signature is over the TSTInfo blob
		verifyBlob, err = tst.Content.ContentInfo.Bytes()
		if err != nil {
			return nil, err
		}
	} else if _, ok := err.(pkcs7.ErrNoAttribute); ok {
		if err := sig.SignerInfo.UnauthenticatedAttributes.GetOne(OidAttributeCounterSign, &tsi); err != nil {
			return nil, err
		}
		// counterSignature is simply a signerinfo. The certificate chain is
		// included in the parent structure, and the timestamp signs the
		// signature blob from the parent signerinfo
		verifyBlob = sig.SignerInfo.EncryptedDigest
		imprintHash, _ = x509tools.PkixDigestToHash(sig.SignerInfo.DigestAlgorithm)
	} else {
		return nil, err
	}
	cert, err := tsi.Verify(verifyBlob, false, certs)
	if err != nil {
		return nil, err
	}
	var signingTime time.Time
	if err := tsi.AuthenticatedAttributes.GetOne(pkcs7.OidAttributeSigningTime, &signingTime); err != nil {
		return nil, err
	}
	return &CounterSignature{
		Signature: pkcs7.Signature{
			SignerInfo:    &tsi,
			Certificate:   cert,
			Intermediates: certs,
		},
		Hash:        imprintHash,
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
		tsig.CounterSignature = ts
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

// Verify the certificate chain of a PKCS#7 signature. If the signature has a
// valid timestamp token attached, then the timestamp is used for validating
// the primary signature's chain, making the signature valid after the
// certificates have expired.
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

// Verify a non-RFC-3161 timestamp token against the given encrypted digest
// from the primary signature.
func VerifyMicrosoftToken(token *pkcs7.ContentInfoSignedData, encryptedDigest []byte) (*CounterSignature, error) {
	sig, err := token.Content.Verify(nil, false)
	if err != nil {
		return nil, err
	}
	content, err := token.Content.ContentInfo.Bytes()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(content, encryptedDigest) {
		return nil, errors.New("timestamp does not match the enclosing signature")
	}
	hash, _ := x509tools.PkixDigestToHash(sig.SignerInfo.DigestAlgorithm)
	var signingTime time.Time
	if err := sig.SignerInfo.AuthenticatedAttributes.GetOne(pkcs7.OidAttributeSigningTime, &signingTime); err != nil {
		return nil, err
	}
	return &CounterSignature{
		Signature:   sig,
		Hash:        hash,
		SigningTime: signingTime,
	}, nil
}
