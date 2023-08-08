package tokencache

import (
	"context"
	"crypto"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/sassoftware/relic/v7/internal/httperror"
	"github.com/sassoftware/relic/v7/token"
)

var (
	buckets = []float64{.01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10, 30, 60}

	MetricOperations = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "token_operation_seconds",
			Help:    "A histogram of latencies for token operations",
			Buckets: buckets,
		},
		[]string{"token", "op"},
	)
	MetricResponses = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "token_responses",
			Help: "Response codes from token operations",
		},
		[]string{"token", "op", "code"},
	)
)

// Metrics wraps a token and updates metrics when methods are called
type Metrics struct {
	token.Token
}

func observe(name, op string, start time.Time, err error) {
	dur := time.Since(start).Seconds()
	var code int
	switch {
	case err == nil:
		code = http.StatusOK
	case errors.Is(err, context.DeadlineExceeded):
		code = http.StatusGatewayTimeout
	case errors.Is(err, context.Canceled):
		code = 499
	case httperror.Temporary(err):
		code = http.StatusServiceUnavailable
	default:
		code = http.StatusInternalServerError
	}
	scode := strconv.FormatInt(int64(code), 10)
	MetricOperations.WithLabelValues(name, op).Observe(dur)
	MetricResponses.WithLabelValues(name, op, scode).Inc()
}

func (m Metrics) Ping(ctx context.Context) (err error) {
	defer func(start time.Time) {
		observe(m.Token.Config().Name(), "ping", start, err)
	}(time.Now())
	return m.Token.Ping(ctx)
}

func (m Metrics) GetKey(ctx context.Context, keyName string) (key token.Key, err error) {
	defer func(start time.Time) {
		observe(m.Token.Config().Name(), "getKey", start, err)
	}(time.Now())
	key, err = m.Token.GetKey(ctx, keyName)
	if err == nil {
		key = metricsKey{Key: key}
	}
	return
}

type metricsKey struct {
	token.Key
}

func (k metricsKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (sig []byte, err error) {
	defer func(start time.Time) {
		observe(k.Config().Token, "sign", start, err)
	}(time.Now())
	return k.Key.Sign(rand, digest, opts)
}

func (k metricsKey) SignContext(ctx context.Context, digest []byte, opts crypto.SignerOpts) (sig []byte, err error) {
	defer func(start time.Time) {
		observe(k.Config().Token, "sign", start, err)
	}(time.Now())
	return k.Key.SignContext(ctx, digest, opts)
}
