package authmodel

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"net/http"

	"github.com/rs/zerolog"
	"github.com/sassoftware/relic/v7/config"
	"github.com/sassoftware/relic/v7/internal/httperror"
	"github.com/sassoftware/relic/v7/internal/realip"
	"github.com/sassoftware/relic/v7/internal/zhttp"
	"github.com/sassoftware/relic/v7/lib/audit"
	"github.com/sassoftware/relic/v7/lib/x509tools"
)

// CertificateAuth requires all callers have a client certificate that either
// has its fingerprint explicitly configured with access, or is signed by a
// configured CA.
type CertificateAuth struct {
	Config *config.Config
}

func (a *CertificateAuth) Authenticate(req *http.Request) (UserInfo, error) {
	peerCerts, err := realip.PeerCertificates(req)
	if err != nil {
		return nil, err
	} else if len(peerCerts) == 0 {
		return nil, httperror.ErrCertificateRequired
	}
	cert := peerCerts[0]
	encoded := fingerprint(cert)
	var useDN bool
	var saved error
	client := a.Config.Clients[encoded]
	if client == nil {
		for _, c2 := range a.Config.Clients {
			match, err := c2.Match(peerCerts)
			if match {
				client = c2
				useDN = true
				break
			} else if err != nil {
				// preserve any potentially interesting validation errors
				saved = err
			}
		}
	}
	if client == nil {
		zhttp.AppendAccessLog(req, func(e *zerolog.Event) {
			e.Str("fingerprint", encoded)
			e.Str("subject", formatSubject(cert))
			if saved != nil {
				e.AnErr("validation_error", saved)
			}
		})
		return nil, httperror.ErrCertificateNotRecognized
	}

	user := &CertificateInfo{
		Name:  client.Nickname,
		Roles: client.Roles,
	}
	if user.Name == "" {
		user.Name = encoded[:12]
	}
	if useDN {
		user.Subject = formatSubject(cert)
	}
	// amend access log with user info
	zhttp.AppendAccessLog(req, func(e *zerolog.Event) {
		e.Str("user", user.Name)
		if user.Subject != "" {
			e.Str("subject", user.Subject)
		}
	})
	return user, nil
}

type CertificateInfo struct {
	Name    string
	Subject string
	Roles   []string
}

func (c *CertificateInfo) AuditContext(info *audit.Info) {
	info.Attributes["client.name"] = c.Name
	if c.Subject != "" {
		info.Attributes["client.dn"] = c.Subject
	}
}

func (c *CertificateInfo) Allowed(keyConf *config.KeyConfig) bool {
	for _, keyRole := range keyConf.Roles {
		for _, clientRole := range c.Roles {
			if keyRole == clientRole {
				return true
			}
		}
	}
	return false
}

func fingerprint(cert *x509.Certificate) string {
	digest := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(digest[:])
}

func formatSubject(cert *x509.Certificate) string {
	return x509tools.FormatPkixName(cert.RawSubject, x509tools.NameStyleOpenSsl)
}
