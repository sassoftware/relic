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

package signinit

import (
	"sync"

	"github.com/sassoftware/relic/cmdline/shared"
	"github.com/sassoftware/relic/lib/pkcs9"
	"github.com/sassoftware/relic/lib/pkcs9/ratelimit"
	"github.com/sassoftware/relic/lib/pkcs9/timestampcache"
	"github.com/sassoftware/relic/signers/pkcs"
)

var (
	mu sync.Mutex
	ts pkcs9.Timestamper
)

func GetTimestamper() (pkcs9.Timestamper, error) {
	mu.Lock()
	defer mu.Unlock()
	var err error
	if ts == nil {
		ts, err = newTimestamper()
	}
	return ts, err
}

func newTimestamper() (timestamper pkcs9.Timestamper, err error) {
	tsconf, err := shared.CurrentConfig.GetTimestampConfig()
	if err != nil {
		return nil, err
	}
	timestamper = pkcs.Timestamper{Config: tsconf}
	if tsconf.RateLimit != 0 {
		timestamper = ratelimit.New(timestamper, tsconf.RateLimit, tsconf.RateBurst)
	}
	if len(tsconf.Memcache) != 0 {
		timestamper, err = timestampcache.New(timestamper, tsconf.Memcache)
		if err != nil {
			return nil, err
		}
	}
	return timestamper, nil
}
