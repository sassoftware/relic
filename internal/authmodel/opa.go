package authmodel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/rs/zerolog"
	"github.com/sassoftware/relic/v7/config"
	"github.com/sassoftware/relic/v7/internal/httperror"
	"github.com/sassoftware/relic/v7/internal/realip"
	"github.com/sassoftware/relic/v7/internal/zhttp"
	"github.com/sassoftware/relic/v7/lib/audit"
)

type PolicyAuth struct {
	cli         *http.Client
	destURL     string
	usesDefault bool
}

func newPolicyAuthenticator(conf *config.Config) (*PolicyAuth, error) {
	usesDefault := !strings.Contains(conf.Server.PolicyURL, "/v1/data")
	return &PolicyAuth{
		cli:         new(http.Client),
		destURL:     conf.Server.PolicyURL,
		usesDefault: usesDefault,
	}, nil
}

func (a *PolicyAuth) Authenticate(req *http.Request) (UserInfo, error) {
	// build input to policy
	input := policyInput{
		Path:  req.URL.Path,
		Query: req.URL.Query(),
		Token: bearerToken(req),
	}
	if peerCerts, err := realip.PeerCertificates(req); err != nil {
		return nil, err
	} else if len(peerCerts) != 0 {
		input.Fingerprint = fingerprint(peerCerts[0])
	}
	if input.Token == "" && input.Fingerprint == "" {
		return nil, httperror.ErrTokenRequired
	}
	result, err := a.evaluate(req.Context(), input)
	if err != nil {
		return nil, err
	}
	// amend access log with authorization metadata
	zhttp.AppendAccessLog(req, func(e *zerolog.Event) {
		if result.Result.Subject != "" {
			e.Str("user", result.Result.Subject)
		}
		e.Object("policy", result)
	})
	if !result.Result.Allow {
		code := http.StatusForbidden
		for _, e := range result.Result.Errors {
			if should401[e] {
				code = http.StatusUnauthorized
			}
		}
		return nil, httperror.TokenAuthorizationError(code, result.Result.Errors)
	}
	return &PolicyInfo{
		Subject:     result.Result.Subject,
		Roles:       result.Result.Roles,
		AllowedKeys: result.Result.AllowedKeys,
		Claims:      result.Result.Claims,
	}, nil
}

func (a *PolicyAuth) evaluate(ctx context.Context, input policyInput) (*policyResponse, error) {
	// marshal request
	var blob []byte
	var err error
	if a.usesDefault {
		// default decision takes just the input
		blob, err = json.Marshal(input)
	} else {
		// posting to a specific package needs a structured request
		blob, err = json.Marshal(policyRequest{Input: input})
	}
	if err != nil {
		return nil, fmt.Errorf("marshaling decision: %w", err)
	}
	preq, err := http.NewRequestWithContext(ctx, http.MethodPost, a.destURL, bytes.NewReader(blob))
	if err != nil {
		return nil, fmt.Errorf("executing decision: %w", err)
	}
	preq.Header.Set("Content-Type", "application/json")
	// execute decision
	resp, err := a.cli.Do(preq)
	if err != nil {
		return nil, fmt.Errorf("executing decision: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		err = httperror.FromResponse(resp)
		return nil, fmt.Errorf("executing decision: %w", err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("parsing decision: %w", err)
	}
	decision := new(policyResponse)
	if err := json.Unmarshal(body, decision); err != nil {
		return nil, fmt.Errorf("parsing decision: %w", err)
	}
	return decision, nil
}

type PolicyInfo struct {
	Subject     string
	Roles       []string
	AllowedKeys []string

	Claims map[string]interface{}
}

// Allowed checks whether the named key is visible to the current user
func (i *PolicyInfo) Allowed(keyConf *config.KeyConfig) bool {
	for _, allowedKey := range i.AllowedKeys {
		if allowedKey == keyConf.Name() {
			return true
		}
	}
	for _, keyRole := range keyConf.Roles {
		for _, allowedRole := range i.Roles {
			if keyRole == allowedRole {
				return true
			}
		}
	}
	return false
}

// AuditContext amends an audit record with the authenticated user's name
// and other relevant details
func (i *PolicyInfo) AuditContext(info *audit.Info) {
	info.Attributes["client.sub"] = i.Subject
	if v := i.Claims["iss"]; v != nil {
		info.Attributes["client.iss"] = v
	}
}

type policyRequest struct {
	Input policyInput `json:"input"`
}

type policyInput struct {
	Path        string     `json:"path"`
	Query       url.Values `json:"query"`
	Token       string     `json:"token"`
	Fingerprint string     `json:"fingerprint"`
}

type policyResponse struct {
	Result struct {
		Allow       bool     `json:"allow"`
		Subject     string   `json:"sub"`
		Errors      []string `json:"errors"`
		Roles       []string `json:"roles"`
		AllowedKeys []string `json:"allowed_keys"`

		Claims map[string]interface{} `json:"claims"`
	} `json:"result"`
	ID string `json:"decision_id"`
}

func (r *policyResponse) MarshalZerologObject(f *zerolog.Event) {
	if r.Result.Allow {
		f.Str("decision", "allowed")
	} else {
		f.Str("decision", "denied")
	}
	if len(r.Result.Errors) != 0 {
		f.Strs("errors", r.Result.Errors)
	}
	if len(r.Result.Claims) != 0 {
		f.Interface("claims", r.Result.Claims)
	}
	if r.ID != "" {
		f.Str("id", r.ID)
	}
}

func bearerToken(req *http.Request) string {
	auth := req.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(auth) < len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
		return ""
	}
	return auth[len(prefix):]
}

var should401 = map[string]bool{
	"token is missing or not well-formed":  true,
	"token issuer is not in known_issuers": true,
	"token is expired":                     true,
	"token is not yet valid":               true,
}
