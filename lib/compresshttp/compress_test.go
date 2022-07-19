package compresshttp_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sassoftware/relic/v7/lib/compresshttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCompress(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/fail" {
			http.NotFound(w, r)
			return
		}
		rbody, err := io.ReadAll(r.Body)
		if assert.NoError(t, err) {
			assert.Len(t, rbody, 8192)
		}
		// write 16384 bytes in two chunks with a flush in between
		d := make([]byte, 8192)
		_, err = w.Write(d)
		require.NoError(t, err)
		w.(http.Flusher).Flush()
		_, err = w.Write(d)
		require.NoError(t, err)
	})
	srv := httptest.NewServer(compresshttp.Middleware(h))
	defer srv.Close()
	for _, ae := range []string{"", "identity", "gzip", "x-snappy-framed"} {
		t.Run("Accept_"+ae, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			d := make([]byte, 8192)
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL, bytes.NewReader(d))
			require.NoError(t, err)
			require.NoError(t, compresshttp.CompressRequest(req, ae))
			if ae != "" {
				req.Header.Set("Accept-Encoding", ae)
			}
			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			assert.Equal(t, http.StatusOK, resp.StatusCode)
			if ae == "identity" {
				assert.Empty(t, resp.Header.Get("Content-Encoding"))
			} else {
				assert.Equal(t, ae, resp.Header.Get("Content-Encoding"))
			}
			require.NoError(t, compresshttp.DecompressResponse(resp))
			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			assert.Len(t, body, 16384)
			assert.Equal(t, compresshttp.AcceptedEncodings, resp.Header.Get("Accept-Encoding"))
		})
	}
	t.Run("Error", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		d := make([]byte, 8192)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL+"/fail", bytes.NewReader(d))
		require.NoError(t, err)
		require.NoError(t, compresshttp.CompressRequest(req, compresshttp.EncodingSnappy))
		req.Header.Set("Accept-Encoding", compresshttp.AcceptedEncodings)
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
		assert.Empty(t, resp.Header.Get("Content-Encoding"))
		require.NoError(t, compresshttp.DecompressResponse(resp))
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Contains(t, string(body), "not found")
	})
	t.Run("Unsupported", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		d := make([]byte, 8192)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL, bytes.NewReader(d))
		require.NoError(t, err)
		req.Header.Set("Content-Encoding", "spam")
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusUnsupportedMediaType, resp.StatusCode)
		assert.Equal(t, compresshttp.AcceptedEncodings, resp.Header.Get("Accept-Encoding"))
	})
}
