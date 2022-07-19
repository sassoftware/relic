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
	"bytes"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"time"
)

func (s *Server) serveDirectory(rw http.ResponseWriter, req *http.Request) {
	sibs := s.Config.Server.Siblings
	if len(sibs) == 0 {
		u := new(url.URL)
		*u = *req.URL
		if req.TLS != nil {
			u.Scheme = "https"
		} else {
			u.Scheme = "http"
		}
		u.Host = req.Host
		sibs = []string{u.String()}
	}
	var buf bytes.Buffer
	shuf := rand.New(rand.NewSource(time.Now().UnixNano()))
	order := shuf.Perm(len(sibs))
	for _, i := range order {
		fmt.Fprintf(&buf, "%s\r\n", sibs[i])
	}
	_, _ = rw.Write(buf.Bytes())
}
