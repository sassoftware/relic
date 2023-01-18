//
// Copyright (c) SAS Institute Inc.
//
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
//

package server

import (
	"net/http"
	"sort"

	"github.com/sassoftware/relic/v7/internal/authmodel"
)

func (s *Server) serveListKeys(rw http.ResponseWriter, req *http.Request) error {
	userInfo := authmodel.RequestInfo(req)
	keys := []string{}
	for key, keyConf := range s.Config.Keys {
		if keyConf.Hide {
			continue
		}
		if keyConf.Alias != "" {
			keyConf = s.Config.Keys[keyConf.Alias]
			if keyConf == nil {
				continue
			}
		}
		if !keyConf.Hide && userInfo.Allowed(keyConf) {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return writeJSON(rw, keys)
}
