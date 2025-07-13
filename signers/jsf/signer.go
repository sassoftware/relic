package jsf

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/gowebpki/jcs"
	"github.com/iancoleman/orderedmap"

	"github.com/sassoftware/relic/v8/lib/certloader"
	"github.com/sassoftware/relic/v8/lib/jsf"
	"github.com/sassoftware/relic/v8/lib/pkcs7"
	"github.com/sassoftware/relic/v8/lib/pkcs9"
	"github.com/sassoftware/relic/v8/signers"
)

const indent = "  "

var JSFSigner = &signers.Signer{
	Name:         "jsf",
	CertTypes:    signers.CertTypeX509,
	TestPath:     testPath,
	Sign:         sign,
	VerifyStream: verify,
}

func init() {
	signers.Register(JSFSigner)
}

func testPath(s string) bool {
	return strings.HasSuffix(s, ".json")
}

func sign(r io.Reader, cert *certloader.Certificate, opts signers.SignOpts) ([]byte, error) {
	jsonData, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	om := orderedmap.New()
	if err := json.Unmarshal(jsonData, om); err != nil {
		return nil, err
	}

	// create signature without value
	sig, err := jsf.CreateSignature(cert.Leaf.PublicKeyAlgorithm, opts.Hash, cert.Certificates)
	if err != nil {
		return nil, err
	}
	om.Set("signature", sig)
	jsonBytes, err := json.MarshalIndent(om, "", indent)
	if err != nil {
		return nil, err
	}

	canonBytes, err := jcs.Transform(jsonBytes)
	if err != nil {
		return nil, err
	}

	msgHash := opts.Hash.HashFunc().New()
	_, err = msgHash.Write(canonBytes)
	if err != nil {
		return nil, err
	}

	sigBytes, err := cert.Signer().Sign(rand.Reader, msgHash.Sum(nil), opts.Hash)
	if err != nil {
		return nil, err
	}

	sig.Value = base64.RawURLEncoding.EncodeToString(sigBytes)
	om.Set("signature", sig)

	outputJson, err := json.MarshalIndent(om, "", indent)
	if err != nil {
		return nil, err
	}

	opts.Audit.SetMimeType("application/json")
	return outputJson, nil
}

func verify(r io.Reader, opts signers.VerifyOpts) ([]*signers.Signature, error) {
	var s *jsf.SignedJSF
	var data map[string]interface{}
	var certs []*x509.Certificate

	jsonData, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(jsonData, &s); err != nil {
		return nil, err
	}

	if err := json.Unmarshal(jsonData, &data); err != nil {
		return nil, err
	}

	signature := s.Signature.ExtractSignature()

	sigBytes, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return nil, err
	}

	// add signature without value field to data
	data["signature"] = s.Signature

	jsonBytes, err := json.MarshalIndent(data, "", indent)
	if err != nil {
		return nil, err
	}

	canonBytes, err := jcs.Transform(jsonBytes)
	if err != nil {
		return nil, err
	}

	certs = opts.TrustedX509
	if len(certs) == 0 {
		certs, err = s.Signature.ParseCertificatePath()
		if err != nil {
			return nil, fmt.Errorf("certificate could not be parsed: %w", err)
		}
		if len(certs) == 0 {
			return nil, fmt.Errorf("no certificate found")
		}
	}

	verifier, err := jsf.CreateVerifier(s.Signature.Algorithm, certs[0], canonBytes, sigBytes)
	if err != nil {
		return nil, err
	}

	if err := verifier.Verify(); err != nil {
		return nil, err
	}

	psig := pkcs7.Signature{Intermediates: certs, Certificate: certs[0]}
	if psig.Certificate == nil {
		return nil, fmt.Errorf("leaf x509 certificate not found")
	}

	return []*signers.Signature{{
		X509Signature: &pkcs9.TimestampedSignature{
			Signature: psig,
		},
	}}, nil
}
