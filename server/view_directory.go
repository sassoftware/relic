/*
 * Copyright (c) SAS Institute Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package server

import (
	"bytes"
	"fmt"
	"math/rand"
	"net/http"
	"time"
)

func (s *Server) serveDirectory() (Response, error) {
	sibs := s.Config.Server.Siblings
	if len(sibs) == 0 {
		return ErrorResponse(http.StatusNotFound), nil
	}
	var buf bytes.Buffer
	shuf := rand.New(rand.NewSource(time.Now().UnixNano()))
	order := shuf.Perm(len(sibs))
	for _, i := range order {
		fmt.Fprintf(&buf, "%s\r\n", sibs[i])
	}
	return StringResponse(http.StatusOK, buf.String()), nil
}
