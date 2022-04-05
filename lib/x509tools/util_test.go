package x509tools_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"testing"

	"github.com/sassoftware/relic/v7/lib/x509tools"
	"github.com/stretchr/testify/assert"
)

func TestSignatureAlgorithm(t *testing.T) {
	t.Parallel()
	assert.Equal(t, x509.SHA256WithRSA, x509tools.X509SignatureAlgorithm(&rsa.PublicKey{}))
	x509tools.ArgRSAPSS = true
	assert.Equal(t, x509.SHA256WithRSAPSS, x509tools.X509SignatureAlgorithm(&rsa.PublicKey{}))
	x509tools.ArgRSAPSS = false
	assert.Equal(t, x509.ECDSAWithSHA256, x509tools.X509SignatureAlgorithm(&ecdsa.PublicKey{Curve: elliptic.P224()}))
	assert.Equal(t, x509.ECDSAWithSHA256, x509tools.X509SignatureAlgorithm(&ecdsa.PublicKey{Curve: elliptic.P256()}))
	assert.Equal(t, x509.ECDSAWithSHA384, x509tools.X509SignatureAlgorithm(&ecdsa.PublicKey{Curve: elliptic.P384()}))
	assert.Equal(t, x509.ECDSAWithSHA512, x509tools.X509SignatureAlgorithm(&ecdsa.PublicKey{Curve: elliptic.P521()}))

	assert.Equal(t, x509.UnknownSignatureAlgorithm, x509tools.X509SignatureAlgorithm(ed25519.PublicKey{}))
}
