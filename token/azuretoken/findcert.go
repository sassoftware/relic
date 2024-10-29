package azuretoken

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
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
	certCli, err := azcertificates.NewClient(baseURL, t.cred, nil)
	if err != nil {
		return nil, err
	}
	cert, err := certCli.GetCertificate(ctx, certName, certVersion, nil)
	if err != nil {
		return nil, err
	}
	return &certRef{
		KeyName:    cert.KID.Name(),
		KeyVersion: cert.KID.Version(),
		CertBlob:   cert.CER,
	}, nil
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
