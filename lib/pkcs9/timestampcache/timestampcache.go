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
	"crypto"
	"crypto/sha256"
	"fmt"
	"log"
	"time"

	"github.com/bradfitz/gomemcache/memcache"
	"github.com/pkg/errors"
	"github.com/sassoftware/relic/lib/pkcs7"
	"github.com/sassoftware/relic/lib/pkcs9"
)

const (
	memcacheTimeout = 1 * time.Second
	memcacheExpiry  = 7 * 24 * time.Hour
)

type timestampCache struct {
	Timestamper pkcs9.Timestamper
	Memcache    *memcache.Client
}

func New(t pkcs9.Timestamper, servers []string) (pkcs9.Timestamper, error) {
	selector := new(memcache.ServerList)
	if err := selector.SetServers(servers...); err != nil {
		return nil, errors.Wrap(err, "parsing memcache servers")
	}
	mc := memcache.NewFromSelector(selector)
	mc.Timeout = memcacheTimeout
	return &timestampCache{t, mc}, nil
}

func (c *timestampCache) Timestamp(data []byte, hash crypto.Hash) (token *pkcs7.ContentInfoSignedData, err error) {
	key := cacheKey("pkcs9", data, hash)
	token = c.get(key)
	if token != nil {
		// hit
		return
	}
	token, err = c.Timestamper.Timestamp(data, hash)
	if err == nil {
		c.set(key, token)
	}
	return
}

func (c *timestampCache) LegacyTimestamp(data []byte) (token *pkcs7.ContentInfoSignedData, err error) {
	key := cacheKey("msft", data, 0)
	token = c.get(key)
	if token != nil {
		// hit
		return
	}
	token, err = c.Timestamper.LegacyTimestamp(data)
	if err == nil {
		c.set(key, token)
	}
	return
}

func cacheKey(prefix string, data []byte, hash crypto.Hash) string {
	d := sha256.New()
	d.Write(data)
	return fmt.Sprintf("%s-%d-%x", prefix, hash, d.Sum(nil))
}

func (c *timestampCache) get(key string) *pkcs7.ContentInfoSignedData {
	item, err := c.Memcache.Get(key)
	if err != nil {
		return nil
	}
	token, err := pkcs7.Unmarshal(item.Value)
	if err != nil {
		log.Printf("warning: failed to parse cached value for timestamp with key %s: %s", key, err)
		return nil
	}
	return token
}

func (c *timestampCache) set(key string, token *pkcs7.ContentInfoSignedData) {
	blob, err := token.Marshal()
	if err != nil {
		log.Printf("warning: failed to save cached timestamp value: %s", err)
		return
	}
	if err := c.Memcache.Set(&memcache.Item{
		Key:        key,
		Value:      blob,
		Expiration: int32(memcacheExpiry / time.Second),
	}); err != nil {
		log.Printf("warning: failed to save cached timestamp value: %s", err)
	}
}
