// Copyright © Leonhard Oelke
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

package signaturecache

import (
	"crypto"
	"fmt"
	"io"
	"time"

	"github.com/bradfitz/gomemcache/memcache"
	"github.com/sassoftware/relic/v8/config"
)

const (
	// Settings for now are the same as the timestamp cache settings
	memcacheTimeout = 1 * time.Second
	memcacheExpiry  = 7 * 24 * time.Hour
)

type SignatureCache interface {
	crypto.Signer
}

type signatureCache struct {
	keyConf  *config.KeyConfig
	signer   crypto.Signer
	Memcache *memcache.Client
}

func New(keyConf *config.KeyConfig, signer crypto.Signer) (SignatureCache, error) {
	selector := new(memcache.ServerList)
	if err := selector.SetServers(keyConf.Memcache...); err != nil {
		return nil, fmt.Errorf("parsing memcache servers: %w", err)
	}
	mc := memcache.NewFromSelector(selector)
	mc.Timeout = memcacheTimeout
	return &signatureCache{keyConf, signer, mc}, nil
}

func (c *signatureCache) Public() crypto.PublicKey {
	return c.signer.Public()
}

func (c *signatureCache) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	cacheKey := fmt.Sprintf("%s-%x", c.keyConf.Name(), digest)

	item, err := c.Memcache.Get(cacheKey)
	if err == nil && item != nil {
		return item.Value, nil
	}

	signature, err := c.signer.Sign(rand, digest, opts)
	if err != nil {
		return nil, err
	}

	_ = c.Memcache.Set(&memcache.Item{
		Key:        cacheKey,
		Value:      signature,
		Expiration: int32(memcacheExpiry / time.Second),
	})

	return signature, nil
}
