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
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/sassoftware/relic/config"
	"github.com/sassoftware/relic/internal/signinit"
	"golang.org/x/crypto/openpgp"
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
	if strings.Contains(path, "/") {
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
	info, err := s.getKeyInfo(request.Context(), keyConf)
	if err != nil {
		return nil, err
	}
	return JSONResponse(info)
}

func (s *Server) getKeyInfo(ctx context.Context, keyConf *config.KeyConfig) (info keyInfo, err error) {
	tok := s.tokens[keyConf.Token]
	if tok == nil {
		return keyInfo{}, fmt.Errorf("missing token \"%s\" for key \"%s\"", keyConf.Token, keyConf.Name())
	}
	cert, _, err := signinit.InitKey(ctx, tok, keyConf.Name())
	if cert.PgpKey != nil {
		info.PGPCertificate, err = marshalPGPCert(cert.PgpKey)
		if err != nil {
			return keyInfo{}, err
		}
	}
	if cert.Leaf != nil {
		info.X509Certificate, err = marshalX509Cert(cert.Certificates)
		if err != nil {
			return keyInfo{}, err
		}
	}
	return
}

// marshal entire X509 certificate chain in PEM format
func marshalX509Cert(certs []*x509.Certificate) (string, error) {
	var buf bytes.Buffer
	for _, cert := range certs {
		block := &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}
		if err := pem.Encode(&buf, block); err != nil {
			return "", err
		}
	}
	return buf.String(), nil
}

// marshal PGP public certificate in ASCII armor
func marshalPGPCert(entity *openpgp.Entity) (string, error) {
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, "PGP PUBLIC KEY BLOCK", nil)
	if err != nil {
		return "", err
	}
	if err := entity.Serialize(w); err != nil {
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", err
	}
	buf.WriteString("\n")
	return buf.String(), nil
}
