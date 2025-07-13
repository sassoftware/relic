package jsf

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
)

type Signature struct {
	Algorithm       string   `json:"algorithm,omitempty"`
	CertificatePath []string `json:"certificatePath,omitempty"`
	Value           string   `json:"value,omitempty"`
}

type SignedJSF struct {
	Signature *Signature `json:"signature,omitempty"`
}

type Verifier interface {
	Populate([]byte, []byte, *x509.Certificate, crypto.Hash)
	Verify() error
}

type BaseVerifier struct {
	message   []byte
	signature []byte
	leaf      *x509.Certificate
	hash      crypto.Hash
}

func (v *BaseVerifier) Populate(msg []byte, sig []byte, leaf *x509.Certificate, hash crypto.Hash) {
	v.message = msg
	v.signature = sig
	v.leaf = leaf
	v.hash = hash
}

type RSAVerifier struct {
	BaseVerifier
}

func (v *RSAVerifier) Verify() error {
	rsaKey, ok := v.leaf.PublicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("key is invalid")
	}

	return rsa.VerifyPKCS1v15(rsaKey, v.hash, v.message, v.signature)
}

type ECDSAVerifier struct {
	BaseVerifier
}

func (v *ECDSAVerifier) Verify() error {
	ecdsaKey, ok := v.leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("key is invalid")
	}
	ok = ecdsa.VerifyASN1(ecdsaKey, v.message, v.signature)

	if !ok {
		return fmt.Errorf("verification failed")
	}

	return nil
}

func CreateVerifier(algorithm string, leaf *x509.Certificate, msg []byte, sig []byte) (Verifier, error) {
	var hash crypto.Hash
	var verifier Verifier

	switch algorithm {
	case "RS256":
		hash = crypto.SHA256
		verifier = &RSAVerifier{}
	case "RS384":
		hash = crypto.SHA384
		verifier = &RSAVerifier{}
	case "RS512":
		hash = crypto.SHA512
		verifier = &RSAVerifier{}
	case "ES256":
		hash = crypto.SHA256
		verifier = &ECDSAVerifier{}
	case "ES384":
		hash = crypto.SHA384
		verifier = &ECDSAVerifier{}
	case "ES512":
		hash = crypto.SHA512
		verifier = &ECDSAVerifier{}
	default:
		return nil, fmt.Errorf("unrecognized JSF algorithm: %s", algorithm)
	}

	msgHash := hash.HashFunc().New()

	_, err := msgHash.Write(msg)
	if err != nil {
		return nil, err
	}

	verifier.Populate(msgHash.Sum(nil), sig, leaf, hash)

	return verifier, nil
}

func (s *Signature) ExtractSignature() string {
	signature := s.Value
	s.Value = ""

	return signature
}

func (s *Signature) ParseCertificatePath() (certs []*x509.Certificate, err error) {
	var certsBytes []byte

	for _, certStr := range s.CertificatePath {
		certBytes, err := base64.RawURLEncoding.DecodeString(certStr)
		if err != nil {
			return nil, err
		}
		certsBytes = append(certsBytes, certBytes...)
	}
	certs, err = x509.ParseCertificates(certsBytes)
	if err != nil {
		return nil, err
	}

	return certs, nil
}

func CreateSignature(pubKeyAlg x509.PublicKeyAlgorithm, hash crypto.Hash, certs []*x509.Certificate) (*Signature, error) {
	var alg string

	// JSF signature algorithms https://cyberphone.github.io/doc/security/jsf.html
	// Since relic currently parses rsa and ecdsa private keys, RS256, RS348, RS512, ES256, ES384, ES512 are supported for now.

	switch pubKeyAlg {
	case x509.RSA:
		alg = "RS"
	case x509.ECDSA:
		alg = "ES"
	default:
		return nil, fmt.Errorf("unsupported JSF algorithm")
	}

	switch hash {
	case crypto.SHA256:
		alg += "256"
	case crypto.SHA384:
		alg += "384"
	case crypto.SHA512:
		alg += "512"
	}

	sig := &Signature{
		Algorithm: alg,
	}

	for _, cert := range certs {
		sig.CertificatePath = append(sig.CertificatePath, base64.RawURLEncoding.EncodeToString(cert.Raw))
	}

	return sig, nil
}
