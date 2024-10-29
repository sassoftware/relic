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
	"context"
	"sync"

	"github.com/sassoftware/relic/v8/cmdline/shared"
	"github.com/sassoftware/relic/v8/lib/pkcs7"
	"github.com/sassoftware/relic/v8/lib/pkcs9"
	"github.com/sassoftware/relic/v8/lib/pkcs9/tsclient"
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
	timestamper, err = tsclient.New(tsconf)
	if err != nil {
		return
	}
	return timestamper, nil
}

// wrapper that selects a named timestamp service
type namedTimestamper struct {
	client pkcs9.Timestamper
	name   string
}

func (t namedTimestamper) Timestamp(ctx context.Context, req *pkcs9.Request) (*pkcs7.ContentInfoSignedData, error) {
	r2 := *req
	r2.Name = t.name
	return t.client.Timestamp(ctx, &r2)
}
