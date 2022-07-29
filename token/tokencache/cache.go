package tokencache

import (
	"bytes"
	"context"
	"sync"
	"time"

	"github.com/sassoftware/relic/v7/token"
)

// Cache keys fetched from an underlying token
type Cache struct {
	token.Token
	keys   map[string]cachedKey
	mu     sync.Mutex
	expiry time.Duration
}

func New(base token.Token, expiry time.Duration) *Cache {
	return &Cache{
		Token:  base,
		keys:   make(map[string]cachedKey),
		expiry: expiry,
	}
}

type cachedKey struct {
	expires time.Time
	key     token.Key
}

func (c *Cache) GetKey(ctx context.Context, keyName string) (token.Key, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	wantKeyID := token.KeyID(ctx)
	cached := c.keys[keyName]
	if cached.key != nil && cached.expires.After(time.Now()) {
		// if caller is looking for a particular key ID, make sure the cached
		// one matches before returning it
		haveKeyID := cached.key.GetID()
		if len(wantKeyID) == 0 || bytes.Equal(wantKeyID, haveKeyID) {
			return cached.key, nil
		}
	}
	key, err := c.Token.GetKey(ctx, keyName)
	if err != nil {
		return nil, err
	}
	if c.expiry > 0 && len(wantKeyID) == 0 {
		// only cache if the caller did not request a specific key ID
		c.keys[keyName] = cachedKey{
			expires: time.Now().Add(c.expiry),
			key:     key,
		}
	}
	return key, nil
}
