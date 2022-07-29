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

package ratelimit

import (
	"context"
	"time"

	"golang.org/x/time/rate"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/sassoftware/relic/v7/lib/pkcs7"
	"github.com/sassoftware/relic/v7/lib/pkcs9"
)

var metricRateLimited = promauto.NewCounter(prometheus.CounterOpts{
	Name: "timestamper_rate_limited_seconds",
	Help: "Cumulative number of seconds waiting for rate limits",
})

type limiter struct {
	Timestamper pkcs9.Timestamper
	Limit       *rate.Limiter
}

func New(t pkcs9.Timestamper, r float64, burst int) pkcs9.Timestamper {
	if r == 0 {
		return t
	}
	if burst < 1 {
		burst = 1
	}
	return &limiter{t, rate.NewLimiter(rate.Limit(r), burst)}
}

func (l *limiter) Timestamp(ctx context.Context, req *pkcs9.Request) (*pkcs7.ContentInfoSignedData, error) {
	start := time.Now()
	if err := l.Limit.Wait(ctx); err != nil {
		return nil, err
	}
	if waited := time.Since(start); waited > 1*time.Millisecond {
		metricRateLimited.Add(time.Since(start).Seconds())
	}
	return l.Timestamper.Timestamp(ctx, req)
}
