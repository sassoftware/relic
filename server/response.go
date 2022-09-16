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
	"encoding/json"
	"errors"
	"net/http"

	"github.com/sassoftware/relic/v7/internal/httperror"
	"github.com/sassoftware/relic/v7/internal/zhttp"
	"github.com/sassoftware/relic/v7/signers/sigerrors"
	"github.com/sassoftware/relic/v7/token"
)

func handleFunc(f func(http.ResponseWriter, *http.Request) error) http.HandlerFunc {
	return func(rw http.ResponseWriter, req *http.Request) {
		ctx := req.Context()
		if srv, ok := ctx.Value(http.ServerContextKey).(*http.Server); ok && srv.WriteTimeout > 0 {
			// timeout request context when WriteTimeout is reached
			ctx, cancel := context.WithTimeout(req.Context(), srv.WriteTimeout)
			defer cancel()
			req = req.WithContext(ctx)
		}
		err := f(rw, req)
		if err == nil {
			return
		}
		if resp, ok := err.(http.Handler); ok {
			resp.ServeHTTP(rw, req)
		} else if h := errToProblem(err); h != nil {
			h.ServeHTTP(rw, req)
		} else {
			zhttp.WriteUnhandledError(rw, req, err, "")
		}
	}
}

func errToProblem(err error) http.Handler {
	if e := new(token.KeyUsageError); errors.As(err, e) {
		return httperror.Problem{
			Status: http.StatusBadRequest,
			Type:   httperror.ProblemKeyUsage,
			Title:  "Incorrect Key Usage",
			Detail: e.Error(),
		}
	} else if e := new(sigerrors.ErrNoCertificate); errors.As(err, e) {
		return httperror.NoCertificateError(e.Type)
	}
	return nil
}

func writeJSON(rw http.ResponseWriter, data interface{}) error {
	blob, err := json.Marshal(data)
	if err != nil {
		return err
	}
	rw.Header().Set("Content-Type", "application/json")
	_, err = rw.Write(blob)
	return err
}
