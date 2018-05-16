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
	"context"
	"crypto"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/sassoftware/relic/internal/signinit"
	"github.com/sassoftware/relic/lib/procutil"
	"github.com/sassoftware/relic/lib/readercounter"
	"github.com/sassoftware/relic/lib/x509tools"
	"github.com/sassoftware/relic/signers"
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
	cert, opts, err := signinit.Init(mod, tok, keyName, hash, flags)
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
	// XXX FIXME audit publish
	s.Logr(request, "Signed package: filename=%s key=%s%s", filename, keyConf.Name(), extra)
	return BytesResponse(blob, opts.Audit.GetMimeType()), nil
}

func (s *Server) showProcError(request *http.Request, cmd *procutil.Command, timeout time.Duration, err error) (Response, error) {
	switch err {
	case context.DeadlineExceeded:
		s.Logr(request, "error: command timed out after %d seconds\nCommand: %s\nOutput:\n%s\n\n",
			timeout/time.Second, cmd.FormatCmdline(), cmd.Output)
		return StringResponse(http.StatusGatewayTimeout, "Signing command timed out"), nil
	case context.Canceled:
		s.Logr(request, "client hung up during signing operation")
		return StringResponse(http.StatusGatewayTimeout, "Signing command timed out"), nil
	}
	s.Logr(request, "error: invoking signing tool: %s\nCommand: %s\nOutput:\n%s\n\n", err, cmd.FormatCmdline(), cmd.Output)
	switch {
	case strings.Contains(cmd.Output, "no certificate of type"):
		return StringResponse(http.StatusBadRequest, "key does not support signatures of this type"), nil
	default:
		return ErrorResponse(http.StatusInternalServerError), nil
	}
}
