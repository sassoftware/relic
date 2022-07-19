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

	"github.com/rs/zerolog/hlog"
	"github.com/sassoftware/relic/v7/internal/authmodel"
	"github.com/sassoftware/relic/v7/internal/httperror"
	"github.com/sassoftware/relic/v7/internal/signinit"
	"github.com/sassoftware/relic/v7/internal/zhttp"
	"github.com/sassoftware/relic/v7/lib/readercounter"
	"github.com/sassoftware/relic/v7/lib/x509tools"
	"github.com/sassoftware/relic/v7/signers"
)

const defaultHash = crypto.SHA256

func (s *Server) serveSign(rw http.ResponseWriter, request *http.Request) error {
	// parse parameters
	query := request.URL.Query()
	keyName := query.Get("key")
	if keyName == "" {
		return httperror.MissingParameterError("key")
	}
	filename := query.Get("filename")
	if filename == "" {
		return httperror.MissingParameterError("filename")
	}
	sigType := query.Get("sigtype")
	// authorize key
	userInfo := authmodel.RequestInfo(request)
	keyConf, err := s.Config.GetKey(keyName)
	if err != nil {
		hlog.FromRequest(request).Err(err).Str("key", keyName).Msg("key not found")
		return httperror.ErrForbidden
	} else if !userInfo.Allowed(keyConf) {
		hlog.FromRequest(request).Error().Str("key", keyName).Msg("access to key denied")
		return httperror.ErrForbidden
	}
	// configure signer
	mod := signers.ByName(sigType)
	if mod == nil {
		hlog.FromRequest(request).Error().Str("sigtype", sigType).Msg("signature type not found")
		return httperror.ErrUnknownSignatureType
	}
	hash := defaultHash
	if digest := request.URL.Query().Get("digest"); digest != "" {
		hash = x509tools.HashByName(digest)
		if hash == 0 {
			hlog.FromRequest(request).Error().Str("digest", digest).Msg("digest type not found")
			return httperror.ErrUnknownDigest
		}
	}
	// parse flags for signer
	flags, err := mod.FlagsFromQuery(query)
	if err != nil {
		hlog.FromRequest(request).Err(err).Str("sigtype", sigType).
			Msg("failed to parse signer arguments")
		return httperror.BadParameterError(err)
	}
	// get key from token and initialize signer context
	tok := s.tokens[keyConf.Token]
	if tok == nil {
		return fmt.Errorf("missing token \"%s\" for key \"%s\"", keyConf.Token, keyName)
	}
	cert, opts, err := signinit.Init(request.Context(), mod, tok, keyName, hash, flags)
	if err != nil {
		return err
	}
	opts.Audit.Attributes["client.ip"] = zhttp.StripPort(request.RemoteAddr)
	opts.Audit.Attributes["client.filename"] = filename
	userInfo.AuditContext(opts.Audit)
	// sign the request stream and output a binpatch or signature blob
	counter := readercounter.New(request.Body)
	blob, err := mod.Sign(counter, cert, *opts)
	if err != nil {
		return err
	}
	opts.Audit.Attributes["perf.size.in"] = counter.N
	opts.Audit.Attributes["perf.size.patch"] = len(blob)
	if err := signinit.PublishAudit(opts.Audit); err != nil {
		return err
	}
	ev := hlog.FromRequest(request).Info().
		Str("key", keyConf.Name()).
		Str("filename", filename)
	if mod.FormatLog != nil {
		ev.Dict("package", mod.FormatLog(opts.Audit))
	}
	ev.Msg("signed package")
	rw.Header().Set("Content-Type", opts.Audit.GetMimeType())
	_, err = rw.Write(blob)
	return err
}
