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
	"crypto"
	"fmt"
	"net/http"

	"github.com/sassoftware/relic/v7/internal/signinit"
	"github.com/sassoftware/relic/v7/lib/readercounter"
	"github.com/sassoftware/relic/v7/lib/x509tools"
	"github.com/sassoftware/relic/v7/signers"
)

const defaultHash = crypto.SHA256

func (s *Server) serveSign(request *http.Request, writer http.ResponseWriter) (res Response, err error) {
	if request.Method != "POST" {
		return ErrorResponse(http.StatusMethodNotAllowed), nil
	}
	// parse parameters
	query := request.URL.Query()
	keyName := query.Get("key")
	if keyName == "" {
		return StringResponse(http.StatusBadRequest, "'key' query parameter is required"), nil
	}
	filename := query.Get("filename")
	if filename == "" {
		return StringResponse(http.StatusBadRequest, "'filename' query parameter is required"), nil
	}
	sigType := query.Get("sigtype")
	keyConf := s.CheckKeyAccess(request, keyName)
	if keyConf == nil {
		s.Logr(request, "access denied to key %s\n", keyName)
		return AccessDeniedResponse, nil
	}
	mod := signers.ByName(sigType)
	if mod == nil {
		s.Logr(request, "error: unknown sigtype: sigtype=%s key=%s", sigType, keyName)
		return StringResponse(http.StatusBadRequest, "unknown sigtype"), nil
	}
	hash := defaultHash
	if digest := request.URL.Query().Get("digest"); digest != "" {
		hash = x509tools.HashByName(digest)
		if hash == 0 {
			s.Logr(request, "error: unknown digest %s", digest)
			return StringResponse(http.StatusBadRequest, "unknown digest"), nil
		}
	}
	flags, err := mod.FlagsFromQuery(query)
	if err != nil {
		s.Logr(request, "error: parsing arguments: %s", err)
		return StringResponse(http.StatusBadRequest, "invalid parameters"), nil
	}
	// get key from token and initialize signer context
	tok := s.tokens[keyConf.Token]
	if tok == nil {
		return nil, fmt.Errorf("missing token \"%s\" for key \"%s\"", keyConf.Token, keyName)
	}
	cert, opts, err := signinit.Init(request.Context(), mod, tok, keyName, hash, flags)
	if err != nil {
		return nil, err
	}
	opts.Audit.Attributes["client.ip"] = GetClientIP(request)
	opts.Audit.Attributes["client.name"] = GetClientName(request)
	opts.Audit.Attributes["client.dn"] = GetClientDN(request)
	opts.Audit.Attributes["client.filename"] = filename
	// sign the request stream and output a binpatch or signature blob
	counter := readercounter.New(request.Body)
	blob, err := mod.Sign(counter, cert, *opts)
	if err != nil {
		return nil, err
	}
	opts.Audit.Attributes["perf.size.in"] = counter.N
	opts.Audit.Attributes["perf.size.patch"] = len(blob)
	var extra string
	if mod.FormatLog != nil {
		extra = mod.FormatLog(opts.Audit)
	}
	if extra != "" {
		extra = " " + extra
	}
	if err := signinit.PublishAudit(opts.Audit); err != nil {
		return nil, err
	}
	s.Logr(request, "Signed package: filename=%s key=%s%s", filename, keyConf.Name(), extra)
	return BytesResponse(blob, opts.Audit.GetMimeType()), nil
}
