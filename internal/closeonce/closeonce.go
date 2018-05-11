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

package closeonce

import (
	"sync"
	"sync/atomic"
)

type Closed struct {
	done uintptr
	mu   sync.Mutex
	err  error
}

func (o *Closed) Closed() bool {
	return atomic.LoadUintptr(&o.done) != 0
}

func (o *Closed) Close(f func() error) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.Closed() {
		return o.err
	}
	o.err = f()
	atomic.StoreUintptr(&o.done, 1)
	o.done = 1
	return o.err
}
