// Copyright © SAS Institute Inc.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package realip

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/sassoftware/relic/v7/internal/zhttp"
)

const (
	forwardedFor   = "X-Forwarded-For"
	forwardedHost  = "X-Forwarded-Host"
	forwardedProto = "X-Forwarded-Proto"
	sslClientCert  = "Ssl-Client-Cert"
)

// Middleware processes headers set by a trusted reverse proxy in front of the
// server. Client IPs are checked against the provided list of networks, and the
// "real" IP passed by the trusted proxy replaces req.RemoteAddr.
func Middleware(trustedProxies []string) (func(http.Handler) http.Handler, error) {
	// parse net list
	trustedNets, err := parseTrusted(trustedProxies)
	if err != nil {
		return nil, err
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			remoteIP, proxied := trustedClient(trustedNets, r)
			r.RemoteAddr = remoteIP
			if proxied {
				ctx := context.WithValue(r.Context(), ctxKeyTrusted, proxied)
				r = r.WithContext(ctx)
			}
			next.ServeHTTP(w, r)
		})
	}, nil
}

// BaseURL returns an estimate of the URL that the client used to access the
// service. Headers like X-Forwarded-Host are taken into account if the
// connection is from a trusted proxy.
func BaseURL(req *http.Request) *url.URL {
	u := &url.URL{Scheme: "http", Host: req.Host}
	if req.TLS != nil {
		u.Scheme = "https"
	}
	if requestTrusted(req) {
		if host := req.Header.Get(forwardedHost); host != "" {
			u.Host = host
		}
		if scheme := req.Header.Get(forwardedProto); scheme != "" {
			u.Scheme = scheme
		}
	}
	return u
}

// PeerCertificates returns the unverified set of certificates provided by the
// client, using the Ssl-Client-Cert header if the connection is from a trusted
// proxy.
func PeerCertificates(req *http.Request) ([]*x509.Certificate, error) {
	if !requestTrusted(req) {
		// direct untrusted connection
		if req.TLS != nil {
			return req.TLS.PeerCertificates, nil
		}
		return nil, nil
	}
	certString := req.Header.Get(sslClientCert)
	if certString == "" {
		return nil, nil
	}
	certString, err := url.PathUnescape(certString)
	if err != nil {
		return nil, fmt.Errorf("%s: invalid URL encoding: %w", sslClientCert, err)
	}
	pemBytes := []byte(certString)
	var ret []*x509.Certificate
	for {
		var b *pem.Block
		b, pemBytes = pem.Decode(pemBytes)
		if b == nil {
			break
		} else if b.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s: parsing certificate %d: %w", sslClientCert, len(ret), err)
		}
		ret = append(ret, cert)
	}
	return ret, nil
}

func parseTrusted(trustedProxies []string) ([]*net.IPNet, error) {
	var trustedNets []*net.IPNet
	for _, v := range trustedProxies {
		var ipnet *net.IPNet
		if strings.ContainsRune(v, '/') {
			var err error
			_, ipnet, err = net.ParseCIDR(v)
			if err != nil {
				return nil, fmt.Errorf("trusted_proxies %q: %w", v, err)
			}
		} else {
			ip := net.ParseIP(v)
			if ip == nil {
				return nil, fmt.Errorf("trusted_proxies %q: invalid IP or IP network", v)
			}
			ipnet = &net.IPNet{IP: ip}
			if ip.To4() != nil {
				ipnet.Mask = net.CIDRMask(32, 32)
			} else {
				ipnet.Mask = net.CIDRMask(128, 128)
			}
		}
		trustedNets = append(trustedNets, ipnet)
	}
	return trustedNets, nil
}

func trustedClient(trustedNets []*net.IPNet, req *http.Request) (string, bool) {
	remoteIP := zhttp.StripPort(req.RemoteAddr)
	if !hopTrusted(trustedNets, remoteIP) {
		// first hop is not trusted
		return remoteIP, false
	}
	// Parse all XFF headers into a single list of hops
	var hops []string
	for _, xff := range req.Header.Values(forwardedFor) {
		for _, hop := range strings.Split(xff, ",") {
			hop = strings.TrimSpace(hop)
			if hop != "" {
				hops = append(hops, hop)
			}
		}
	}
	// Check each hop, starting from the closest one to us
	for i := len(hops) - 1; i >= 0; i-- {
		nextHop := strings.TrimSpace(hops[i])
		if !hopTrusted(trustedNets, nextHop) {
			// The previous hop is trusted but this one is not, so this is the
			// best client IP
			return nextHop, true
		}
	}
	// No untrusted hops were found, so whatever the last one in the chain is is
	// the client IP.
	if len(hops) != 0 {
		return hops[0], true
	}
	return remoteIP, false
}

func hopTrusted(trustedNets []*net.IPNet, addr string) bool {
	if addr == "@" {
		// UNIX socket
		return true
	}
	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}
	for _, p := range trustedNets {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

type ctxKey int

var ctxKeyTrusted ctxKey = 1

func requestTrusted(req *http.Request) bool {
	trusted, _ := req.Context().Value(ctxKeyTrusted).(bool)
	return trusted
}
