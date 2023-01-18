package azuretoken

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

type certRef struct {
	KeyName, KeyVersion string
	CertBlob            []byte
}

// encode the exact key version into our ID field so that when we're being used
// via a worker token, callers get a consistent signing key from GetKey() to
// Sign()
func (r certRef) KeyID() []byte {
	return []byte(r.KeyName + "/" + r.KeyVersion)
}

// decode a previous KeyID() call back into a key version
func refFromKeyID(keyID []byte) *certRef {
	words := bytes.Split(keyID, []byte{'/'})
	if len(words) != 2 {
		return nil
	}
	return &certRef{
		KeyName:    string(words[0]),
		KeyVersion: string(words[1]),
	}
}

// load the named certificate version and return the key it references
func (t *kvToken) loadCertificateVersion(ctx context.Context, baseURL, certName, certVersion string) (*certRef, error) {
	cert, err := t.cli.GetCertificate(ctx, baseURL, certName, certVersion)
	if err != nil {
		return nil, err
	}
	if cert.Kid == nil {
		return nil, errors.New("missing key ID in certificate")
	}
	keyWords, _, err := parseKeyURL(*cert.Kid)
	if err != nil {
		return nil, err
	}
	if len(keyWords) != 4 || keyWords[1] != "keys" {
		return nil, fmt.Errorf("unexpected format for key ID: %s", *cert.Kid)
	}
	var blob []byte
	if cert.Cer != nil {
		blob = *cert.Cer
	}
	return &certRef{
		KeyName:    keyWords[2],
		KeyVersion: keyWords[3],
		CertBlob:   blob,
	}, nil
}

// load the latest enabled version of the named certificate and return the key it references
func (t *kvToken) loadCertificateLatest(ctx context.Context, baseURL, certName string) (*certRef, error) {
	// list all versions of the cert and pick the latest enabled one
	certs, err := t.cli.GetCertificateVersions(ctx, baseURL, certName, nil)
	if err != nil {
		return nil, fmt.Errorf("listing cert versions: %w", err)
	}
	var best string
	var bestNBF time.Time
	for certs.NotDone() {
		for _, cert := range certs.Values() {
			if cert.Attributes == nil || cert.Attributes.Enabled == nil || !*cert.Attributes.Enabled {
				continue
			}
			if cert.Attributes.NotBefore == nil || cert.ID == nil {
				continue
			}
			nbf := time.Time(*cert.Attributes.NotBefore)
			if nbf.After(bestNBF) {
				best, bestNBF = *cert.ID, nbf
			}
		}
		if err := certs.NextWithContext(ctx); err != nil {
			return nil, fmt.Errorf("listing cert versions: %w", err)
		}
	}
	// parse the cert ID and load it
	if best == "" || bestNBF.IsZero() {
		return nil, fmt.Errorf("cert %s has no enabled versions", certName)
	}
	words, _, err := parseKeyURL(best)
	if err != nil {
		return nil, fmt.Errorf("cert %s has invalid key ID: %w", certName, err)
	}
	if len(words) != 4 || words[1] != "certificates" {
		return nil, fmt.Errorf("unexpected format for certificate ID: %s", best)
	}
	return t.loadCertificateVersion(ctx, baseURL, words[2], words[3])
}

var errKeyID = errors.New("id: expected URL of a certificate, certificate version, or key version")

func parseKeyURL(keyURL string) (words []string, baseURL string, err error) {
	if keyURL == "" {
		return nil, "", errKeyID
	}
	// deconstruct URL to call GetKey so it can put it back together again
	u, err := url.Parse(keyURL)
	if err != nil {
		return nil, "", fmt.Errorf("id: %w", err)
	} else if u.Scheme == "" || u.Host == "" {
		return nil, "", errKeyID
	}
	words = strings.Split(u.Path, "/")
	u.Path = ""
	baseURL = u.String()
	return words, baseURL, nil
}
