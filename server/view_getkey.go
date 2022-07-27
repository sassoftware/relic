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

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"

	"github.com/go-chi/chi/v5"
	"github.com/sassoftware/relic/v7/config"
	"github.com/sassoftware/relic/v7/internal/authmodel"
	"github.com/sassoftware/relic/v7/internal/httperror"
	"github.com/sassoftware/relic/v7/internal/signinit"
)

type keyInfo struct {
	X509Certificate string
	PGPCertificate  string
}

func (s *Server) serveGetKey(rw http.ResponseWriter, req *http.Request) error {
	userInfo := authmodel.RequestInfo(req)
	keyName := chi.URLParam(req, "key")
	keyConf, err := s.Config.GetKey(keyName)
	if err == nil && userInfo.Allowed(keyConf) {
		info, err := s.getKeyInfo(req.Context(), keyConf)
		if err != nil {
			return err
		}
		return writeJSON(rw, info)
	}
	return httperror.ErrForbidden
}

func (s *Server) getKeyInfo(ctx context.Context, keyConf *config.KeyConfig) (keyInfo, error) {
	tok := s.tokens[keyConf.Token]
	if tok == nil {
		return keyInfo{}, fmt.Errorf("missing token \"%s\" for key \"%s\"", keyConf.Token, keyConf.Name())
	}
	cert, _, err := signinit.InitKey(ctx, tok, keyConf.Name())
	if err != nil {
		return keyInfo{}, err
	}
	var info keyInfo
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
	return info, nil
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
