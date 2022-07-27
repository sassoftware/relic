package realip

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTrusted(t *testing.T) {
	nets, err := parseTrusted([]string{"10.0.0.0/8"})
	require.NoError(t, err)
	cases := []struct {
		Case, IP, XFF, Expected string
		Trusted                 bool
	}{
		// direct from an untrusted IP
		{"Direct", "172.16.0.1", "", "172.16.0.1", false},
		// direct from a trusted IP
		{"DirectInternal", "10.0.0.1", "", "10.0.0.1", false},
		// direct from an untrusted IP with an untrusted hop
		{"DirectUntrusted", "10.0.0.1", "", "10.0.0.1", false},
		// connected via trusted proxy
		{"OneHop", "10.0.0.1", "192.168.100.1", "192.168.100.1", true},
		// connected via trusted proxy and the client is also a trusted IP
		{"OneHopInternal", "10.0.0.1", "10.0.0.2", "10.0.0.2", true},
		// connected via trusted proxy with an untrusted hop
		{"OneHopUntrusted", "10.0.0.1", "172.16.0.1, 192.168.100.1", "192.168.100.1", true},
		// connected via two trusted proxies
		{"TwoHops", "10.0.0.1", "192.168.100.1, 10.0.0.2", "192.168.100.1", true},
	}
	for _, c := range cases {
		t.Run(c.Case, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = c.IP + ":12345"
			if c.XFF != "" {
				req.Header.Set("X-Forwarded-For", c.XFF)
			}
			actual, trusted := trustedClient(nets, req)
			assert.Equal(t, c.Expected, actual)
			assert.Equal(t, c.Trusted, trusted)
			req.Header.Del("X-Forwarded-For")

		})
		if !strings.ContainsRune(c.XFF, ',') {
			continue
		}
		// do it again with separate XFF headers
		t.Run(c.Case+"Multi", func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = c.IP + ":12345"
			for _, v := range strings.Split(c.XFF, ",") {
				req.Header.Add("X-Forwarded-For", v)
			}
			actual, trusted := trustedClient(nets, req)
			assert.Equal(t, c.Expected, actual)
			assert.Equal(t, c.Trusted, trusted)
		})
	}
}
