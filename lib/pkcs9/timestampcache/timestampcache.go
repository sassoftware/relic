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

package timestampcache

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/bradfitz/gomemcache/memcache"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/rs/zerolog/log"

	"github.com/sassoftware/relic/v7/lib/pkcs7"
	"github.com/sassoftware/relic/v7/lib/pkcs9"
)

const (
	memcacheTimeout = 1 * time.Second
	memcacheExpiry  = 7 * 24 * time.Hour
)

var metricHits = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "timestamper_cache",
		Help: "Timestamper cache hit and miss count",
	},
	[]string{"result"},
)

type timestampCache struct {
	Timestamper pkcs9.Timestamper
	Memcache    *memcache.Client
}

func New(t pkcs9.Timestamper, servers []string) (pkcs9.Timestamper, error) {
	selector := new(memcache.ServerList)
	if err := selector.SetServers(servers...); err != nil {
		return nil, fmt.Errorf("parsing memcache servers: %w", err)
	}
	mc := memcache.NewFromSelector(selector)
	mc.Timeout = memcacheTimeout
	return &timestampCache{t, mc}, nil
}

func (c *timestampCache) Timestamp(ctx context.Context, req *pkcs9.Request) (*pkcs7.ContentInfoSignedData, error) {
	key := cacheKey(req)
	item, err := c.Memcache.Get(key)
	if err == nil {
		token, err := pkcs7.Unmarshal(item.Value)
		if err == nil {
			metricHits.WithLabelValues("hit").Inc()
			return token, nil
		}
		log.Warn().Err(err).Str("key", key).Msg("failed to parse cached value for timestamp")
		// bad cached value, fall through
	}
	token, err := c.Timestamper.Timestamp(ctx, req)
	if err == nil {
		blob, err := token.Marshal()
		if err != nil {
			return nil, err
		}
		if err := c.Memcache.Set(&memcache.Item{
			Key:        key,
			Value:      blob,
			Expiration: int32(memcacheExpiry / time.Second),
		}); err != nil {
			log.Warn().Err(err).Msg("failed to save cached value for timestamp")
		}
		metricHits.WithLabelValues("miss").Inc()
	}
	return token, err
}

func cacheKey(req *pkcs9.Request) string {
	d := sha256.New()
	d.Write(req.EncryptedDigest)
	prefix := "pkcs9"
	if req.Legacy {
		prefix = "msft"
	}
	return fmt.Sprintf("%s-%d-%x", prefix, req.Hash, d.Sum(nil))
}
