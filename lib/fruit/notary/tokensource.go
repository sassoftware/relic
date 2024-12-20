package notary

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/oauth2"
)

// Our TokenSource is wrapped with ReuseTokenSource to renew automatically, so
// this should be long enough to avoid wasting computational effort but
// otherwise does not matter much. The API rejects anything greater than 20
// minutes.
const tokenExpiry = 5 * time.Minute

func newConnectTokenSource(keyFile, keyID, issuer string) (oauth2.TokenSource, error) {
	// Parse private key
	pemBytes, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	pemBlock, _ := pem.Decode(pemBytes)
	if pemBlock == nil || pemBlock.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("parsing %s: expected PRIVATE KEY", keyFile)
	}
	priv, err := x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", keyFile, err)
	}
	ecPriv, ok := priv.(*ecdsa.PrivateKey)
	if !ok || ecPriv.Curve.Params().BitSize != 256 {
		return nil, fmt.Errorf("parsing %s: expected ECDSA P-256 private key", keyFile)
	}

	// Build token header
	opts := &jose.SignerOptions{ExtraHeaders: map[jose.HeaderKey]any{
		"kid": keyID,
		"typ": "JWT",
	}}
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       ecPriv,
	}, opts)
	if err != nil {
		return nil, err
	}
	src := &connectTokenSource{
		issuer: issuer,
		signer: signer,
	}
	return src, nil
}

type connectTokenSource struct {
	issuer string
	signer jose.Signer
}

func (s *connectTokenSource) Token() (*oauth2.Token, error) {
	// Build token claims
	issuedAt := time.Now()
	expiresAt := time.Now().Add(tokenExpiry)
	claims := jwt.Claims{
		Issuer:   s.issuer,
		Audience: jwt.Audience{"appstoreconnect-v1"},
		IssuedAt: jwt.NewNumericDate(issuedAt),
		Expiry:   jwt.NewNumericDate(expiresAt),
	}

	// Sign token
	token, err := jwt.Signed(s.signer).Claims(claims).Serialize()
	if err != nil {
		return nil, fmt.Errorf("signing oauth bearer jwt: %w", err)
	}
	return &oauth2.Token{
		AccessToken: token,
		Expiry:      expiresAt,
	}, nil
}
