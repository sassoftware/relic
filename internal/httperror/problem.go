package httperror

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/rs/zerolog"
	"github.com/sassoftware/relic/v7/internal/zhttp"
)

// Problem implements a RFC 7807 HTTP "problem" response
type Problem struct {
	Status int    `json:"status"`
	Type   string `json:"type"`

	Title    string `json:"title,omitempty"`
	Detail   string `json:"detail,omitempty"`
	Instance string `json:"instance,omitempty"`

	// error-specific
	Param  string   `json:"param,omitempty"`
	Errors []string `json:"errors,omitempty"`
}

func (e Problem) Error() string {
	title := e.Title
	if title == "" {
		title = "[" + e.Type + "]"
	}
	m := fmt.Sprintf("HTTP %d %s", e.Status, title)
	if e.Detail != "" {
		m += ": " + e.Detail
	}
	return m
}

func (e Problem) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if e.Type != "" {
		zhttp.AppendAccessLog(req, func(ev *zerolog.Event) {
			ev.Str("problem", e.Type)
		})
	}
	blob, _ := json.MarshalIndent(e, "", "  ")
	rw.Header().Set("Content-Type", "application/problem+json")
	rw.WriteHeader(e.Status)
	_, _ = rw.Write(blob)
}

func (e Problem) Temporary() bool {
	return statusIsTemporary(e.Status)
}

const (
	ProblemBase     = "https://relic.sas.com/"
	ProblemKeyUsage = ProblemBase + "key-usage"
)

var (
	ErrForbidden = &Problem{
		Status: http.StatusForbidden,
		Type:   ProblemBase + "forbidden",
	}
	ErrCertificateRequired = &Problem{
		Status: http.StatusUnauthorized,
		Type:   ProblemBase + "certificate-required",
		Detail: "A client certificate must be provided to use this service",
	}
	ErrCertificateNotRecognized = &Problem{
		Status: http.StatusUnauthorized,
		Type:   ProblemBase + "certificate-not-recognized",
		Detail: "The provided client certificate was not recognized or does not grant access to any resources",
	}
	ErrTokenRequired = &Problem{
		Status: http.StatusUnauthorized,
		Type:   ProblemBase + "token-required",
		Detail: "A bearer token or client certificate must be provided to use this service",
	}
	ErrUnknownSignatureType = &Problem{
		Status: http.StatusBadRequest,
		Type:   ProblemBase + "unknown-signature-type",
		Detail: "Unknown signature type specified",
	}
	ErrUnknownDigest = &Problem{
		Status: http.StatusBadRequest,
		Type:   ProblemBase + "unknown-digest-algorithm",
		Detail: "Unknown digest algorithm specified",
	}
)

func MissingParameterError(param string) Problem {
	return Problem{
		Status: http.StatusBadRequest,
		Type:   ProblemBase + "missing-parameter",
		Detail: "Parameter " + param + " is required",
		Param:  param,
	}
}

func BadParameterError(err error) Problem {
	return Problem{
		Status: http.StatusBadRequest,
		Type:   ProblemBase + "bad-parameter",
		Detail: "Failed to parse signer parameters: " + err.Error(),
	}
}

func TokenAuthorizationError(code int, errors []string) Problem {
	p := Problem{
		Status: code,
		Type:   ProblemBase + "token-authorization-failed",
		Errors: errors,
	}
	if len(p.Errors) == 0 {
		p.Detail = "denied by policy"
	} else {
		p.Detail = strings.Join(errors, ", ")
	}
	return p
}

func NoCertificateError(certType string) Problem {
	return Problem{
		Status: http.StatusBadRequest,
		Type:   ProblemBase + "certificate-not-defined",
		Detail: "No certificate of type \"" + certType + "\" is defined for this key",
	}
}
