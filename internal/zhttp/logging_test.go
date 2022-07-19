package zhttp

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/hlog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoggingMiddleware(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/dontlog":
			DontLog(r)
		case "/changeme":
			r.URL.Path = "/changed"
		default:
			http.NotFound(w, r)
			return
		}
		// updates to the log context affect every message
		hlog.FromRequest(r).UpdateContext(func(c zerolog.Context) zerolog.Context {
			return c.Str("append1", "always")
		})
		// append only to the access log without affecting the context
		AppendAccessLog(r, func(e *zerolog.Event) {
			e.Str("append2", "access")
		})
		hlog.FromRequest(r).Info().Msg("a message")
	})
	var buf bytes.Buffer
	logger := zerolog.New(&buf)
	now := fakeTime()
	mw := LoggingMiddleware(
		WithLogger(logger),
		func(lc *loggingConfig) { lc.now = now },
	)
	newReq := func(path string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.RemoteAddr = "192.168.1.1:12345"
		r.Header.Set("X-Request-Id", "00000000")
		r.Header.Set("User-Agent", "unittest")
		return r
	}

	t.Run("Changed", func(t *testing.T) {
		buf.Reset()
		r, w := newReq("/changeme"), httptest.NewRecorder()
		mw(h).ServeHTTP(w, r)
		resp := w.Result()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, `{"level":"info","ip":"192.168.1.1","req_id":"00000000","append1":"always","message":"a message"}
{"level":"info","ip":"192.168.1.1","req_id":"00000000","append1":"always","method":"GET","url":"/changed","status":200,"len":0,"dur":1000,"ttfb":2000,"ua":"unittest","append2":"access"}
`, buf.String())
	})
	t.Run("DontLog", func(t *testing.T) {
		buf.Reset()
		r, w := newReq("/dontlog"), httptest.NewRecorder()
		mw(h).ServeHTTP(w, r)
		resp := w.Result()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, `{"level":"info","ip":"192.168.1.1","req_id":"00000000","append1":"always","message":"a message"}
`, buf.String())
	})
}

func fakeTime() func() time.Time {
	ts := time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC)
	return func() time.Time {
		ts = ts.Add(time.Second)
		return ts
	}
}
