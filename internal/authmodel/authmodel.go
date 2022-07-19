package authmodel

import (
	"context"
	"net/http"

	"github.com/sassoftware/relic/v7/config"
	"github.com/sassoftware/relic/v7/internal/zhttp"
	"github.com/sassoftware/relic/v7/lib/audit"
)

type ctxKey int

var ctxKeyUserInfo ctxKey = 1

type Authenticator interface {
	Authenticate(req *http.Request) (UserInfo, error)
}

type UserInfo interface {
	// Allowed checks whether the named key is visible to the current user
	Allowed(*config.KeyConfig) bool
	// AuditContext amends an audit record with the authenticated user's name
	// and other relevant details
	AuditContext(info *audit.Info)
}

// New creates an authenticator based on the provided server configuration
func New(conf *config.Config) (Authenticator, error) {
	switch {
	case conf.Server.PolicyURL != "":
		return newPolicyAuthenticator(conf)
	default:
		return &CertificateAuth{Config: conf}, nil
	}
}

// Middleware checks each request for authentication. If successful, the user's
// information is appended to the log context and request context. If not, an
// error is returned and the inner handler is skipped.
func Middleware(a Authenticator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			info, err := a.Authenticate(r)
			if err != nil {
				if h, ok := err.(http.Handler); ok {
					h.ServeHTTP(w, r)
				} else {
					zhttp.WriteUnhandledError(w, r, err, "")
				}
				return
			} else if info == nil {
				panic("authenticator returned nil without an error")
			}
			ctx := r.Context()
			ctx = context.WithValue(ctx, ctxKeyUserInfo, info)
			r = r.WithContext(ctx)
			next.ServeHTTP(w, r)
		})
	}
}

// RequestInfo returns information about the calling user
func RequestInfo(req *http.Request) UserInfo {
	info, ok := req.Context().Value(ctxKeyUserInfo).(UserInfo)
	if !ok {
		// middleware should guarantee this is always present, otherwise
		// something is seriously wrong
		panic("userinfo missing from request context")
	}
	return info
}
