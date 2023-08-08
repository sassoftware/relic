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

package tsclient

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sassoftware/relic/v7/config"
	"github.com/sassoftware/relic/v7/lib/pkcs7"
	"github.com/sassoftware/relic/v7/lib/pkcs9"
	"github.com/sassoftware/relic/v7/lib/pkcs9/ratelimit"
	"github.com/sassoftware/relic/v7/lib/pkcs9/timestampcache"
	"github.com/sassoftware/relic/v7/lib/x509tools"
)

type tsClient struct {
	conf   *config.TimestampConfig
	client *http.Client
}

var (
	buckets = []float64{.01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10}

	metricCount = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "timestamper_request_count",
			Help: "Outcome of timestamper requests",
		},
		[]string{"code"},
	)
	metricDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "timestamper_request_duration_seconds",
			Help:    "Histogram of timestamper request durations",
			Buckets: buckets,
		},
		nil,
	)
)

func New(conf *config.TimestampConfig) (t pkcs9.Timestamper, err error) {
	tlsconf := &tls.Config{}
	if err := x509tools.LoadCertPool(conf.CaCert, tlsconf); err != nil {
		return nil, err
	}
	client := &http.Client{
		Timeout: time.Second * time.Duration(conf.Timeout),
		Transport: &http.Transport{
			TLSClientConfig: tlsconf,
		},
	}
	client.Transport = promhttp.InstrumentRoundTripperCounter(metricCount, client.Transport)
	client.Transport = promhttp.InstrumentRoundTripperDuration(metricDuration, client.Transport)
	t = tsClient{conf, client}
	if conf.RateLimit != 0 {
		t = ratelimit.New(t, conf.RateLimit, conf.RateBurst)
	}
	if len(conf.Memcache) != 0 {
		t, err = timestampcache.New(t, conf.Memcache)
		if err != nil {
			return nil, err
		}
	}
	return
}

func (c tsClient) Timestamp(ctx context.Context, req *pkcs9.Request) (*pkcs7.ContentInfoSignedData, error) {
	var urls []string
	if req.Legacy {
		urls = c.conf.MsURLs
		if len(urls) == 0 {
			return nil, errors.New("timestamp.msurls is empty")
		}
	} else {
		urls = c.conf.URLs
		if len(urls) == 0 {
			return nil, errors.New("timestamp.urls is empty")
		}
	}
	imprint := req.EncryptedDigest
	if !req.Legacy {
		d := req.Hash.New()
		d.Write(imprint)
		imprint = d.Sum(nil)
	}
	var err error
	for _, url := range urls {
		if err != nil {
			log.Printf("warning: timestamping failed: %s\n  trying next server %s...\n", err, url)
		}
		var token *pkcs7.ContentInfoSignedData
		token, err = c.do(ctx, url, req, imprint)
		if err == nil {
			return token, nil
		}
		if ctx.Err() != nil {
			return nil, err
		}
	}
	return nil, fmt.Errorf("timestamping failed: %w", err)
}

func (c tsClient) do(ctx context.Context, url string, req *pkcs9.Request, imprint []byte) (*pkcs7.ContentInfoSignedData, error) {
	var msg *pkcs9.TimeStampReq
	var httpReq *http.Request
	var err error
	if !req.Legacy {
		msg, httpReq, err = pkcs9.NewRequest(url, req.Hash, imprint)
	} else {
		httpReq, err = pkcs9.NewLegacyRequest(url, imprint)
	}
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("User-Agent", config.UserAgent)
	resp, err := c.client.Do(httpReq.WithContext(ctx))
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, err
	} else if resp.StatusCode != 200 {
		return nil, fmt.Errorf("%s: HTTP %s\n%s", url, resp.Status, body)
	}
	if req.Legacy {
		return pkcs9.ParseLegacyResponse(body)
	}
	return msg.ParseResponse(body)
}
