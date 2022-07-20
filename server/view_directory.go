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
	"strings"

	"github.com/sassoftware/relic/v7/internal/authmodel"
	"github.com/sassoftware/relic/v7/internal/realip"
)

func (s *Server) serveDirectory(rw http.ResponseWriter, req *http.Request) error {
	sibs := append([]string{}, s.Config.Server.Siblings...)
	rand.Shuffle(len(sibs), func(i, j int) { sibs[i], sibs[j] = sibs[j], sibs[i] })
	if !strings.Contains(req.Header.Get("Accept"), "json") {
		// legacy path
		var buf bytes.Buffer
		if len(sibs) == 0 {
			u := realip.BaseURL(req)
			sibs = []string{u.String()}
		}
		for _, h := range sibs {
			_, _ = fmt.Fprintf(&buf, "%s\r\n", h)
		}
		var err error
		_, err = rw.Write(buf.Bytes())
		return err
	}

	md := authmodel.Metadata{
		Hosts: sibs,
		Auth: []authmodel.AuthMetadata{
			{Type: authmodel.AuthTypeCertificate},
		},
	}
	if _, ok := s.auth.(*authmodel.PolicyAuth); ok {
		md.Auth = append(md.Auth, authmodel.AuthMetadata{Type: authmodel.AuthTypeBearerToken})
		if aad := s.Config.Server.AzureAD; aad != nil {
			md.Auth = append(md.Auth, authmodel.AuthMetadata{
				Type:      authmodel.AuthTypeAzureAD,
				Authority: aad.Authority,
				ClientID:  aad.ClientID,
				Scopes:    aad.Scopes,
			})
		}
	}
	return writeJSON(rw, md)
}
