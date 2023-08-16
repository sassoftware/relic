package tokencache

import (
	"context"
	"crypto"
	"io"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/sassoftware/relic/v7/token"
	"golang.org/x/time/rate"
)

var metricRateLimited = promauto.NewCounter(prometheus.CounterOpts{
	Name: "token_operation_limited_seconds",
	Help: "Cumulative number of seconds waiting for rate limits",
})

type RateLimited struct {
	token.Token
	limit *rate.Limiter
}

func NewLimiter(base token.Token, limit float64, burst int) *RateLimited {
	if burst < 1 {
		burst = 1
	}
	return &RateLimited{
		Token: base,
		limit: rate.NewLimiter(rate.Limit(limit), burst),
	}
}

type rateLimitedKey struct {
	token.Key
	limit *rate.Limiter
}

func (r *RateLimited) GetKey(ctx context.Context, keyName string) (token.Key, error) {
	start := time.Now()
	if err := r.limit.Wait(ctx); err != nil {
		return nil, err
	}
	if waited := time.Since(start); waited > 1*time.Millisecond {
		metricRateLimited.Add(time.Since(start).Seconds())
	}
	key, err := r.Token.GetKey(ctx, keyName)
	if err != nil {
		return nil, err
	}
	return &rateLimitedKey{
		Key:   key,
		limit: r.limit,
	}, nil
}

func (k *rateLimitedKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (sig []byte, err error) {
	start := time.Now()
	if err := k.limit.Wait(context.Background()); err != nil {
		return nil, err
	}
	if waited := time.Since(start); waited > 1*time.Millisecond {
		metricRateLimited.Add(time.Since(start).Seconds())
	}
	return k.Key.Sign(rand, digest, opts)
}

func (k *rateLimitedKey) SignContext(ctx context.Context, digest []byte, opts crypto.SignerOpts) (sig []byte, err error) {
	start := time.Now()
	if err := k.limit.Wait(ctx); err != nil {
		return nil, err
	}
	if waited := time.Since(start); waited > 1*time.Millisecond {
		metricRateLimited.Add(time.Since(start).Seconds())
	}
	return k.Key.SignContext(ctx, digest, opts)
}
