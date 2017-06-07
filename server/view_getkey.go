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
	"encoding/pem"
	"net/http"
	"net/url"
	"strings"

	"github.com/sassoftware/relic/lib/certloader"
	"golang.org/x/crypto/openpgp/armor"
)

type keyInfo struct {
	X509Certificate string
	PGPCertificate  string
}

func (s *Server) serveGetKey(request *http.Request) (res Response, err error) {
	if request.Method != "GET" {
		return ErrorResponse(http.StatusMethodNotAllowed), nil
	}
	path := request.URL.Path[6:]
	if strings.Index(path, "/") >= 0 {
		return ErrorResponse(http.StatusBadRequest), nil
	}
	keyName, err := url.PathUnescape(path)
	if err != nil {
		return ErrorResponse(http.StatusBadRequest), nil
	}
	keyConf := s.CheckKeyAccess(request, keyName)
	if keyConf == nil {
		s.Logr(request, "access denied to key %s\n", keyName)
		return AccessDeniedResponse, nil
	}
	var info keyInfo
	var paths []string
	if keyConf.PgpCertificate != "" {
		paths = append(paths, keyConf.PgpCertificate)
	}
	if keyConf.X509Certificate != "" {
		paths = append(paths, keyConf.X509Certificate)
	}
	certs, err := certloader.LoadAnyCerts(paths)
	if err != nil {
		return nil, err
	}
	if len(certs.PGPCerts) != 0 {
		var buf bytes.Buffer
		w, err := armor.Encode(&buf, "PGP PUBLIC KEY BLOCK", nil)
		if err != nil {
			return nil, err
		}
		for _, cert := range certs.PGPCerts {
			if err := cert.Serialize(w); err != nil {
				return nil, err
			}
		}
		if err := w.Close(); err != nil {
			return nil, err
		}
		buf.WriteString("\n")
		info.PGPCertificate = buf.String()
	}
	if len(certs.X509Certs) != 0 {
		var buf bytes.Buffer
		for _, cert := range certs.X509Certs {
			block := &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}
			if err := pem.Encode(&buf, block); err != nil {
				return nil, err
			}
		}
		info.X509Certificate = buf.String()
	}
	return JSONResponse(info)
}
