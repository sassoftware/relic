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
	"io"
	"net"
	"net/http"
	"os"

	"gerrit-pdt.unx.sas.com/tools/relic.git/pgptoken"
	"gerrit-pdt.unx.sas.com/tools/relic.git/signrpm"
)

func (handler *Handler) serveSignRpm(request *http.Request) (Response, error) {
	if request.Method != "POST" {
		return ErrorResponse(http.StatusMethodNotAllowed), nil
	}
	query := request.URL.Query()
	keyName := query.Get("key")
	if keyName == "" {
		return StringResponse(http.StatusBadRequest, "'key' query parameter is required"), nil
	}
	key, ok := handler.KeyMap[keyName]
	if !ok {
		return StringResponse(http.StatusBadRequest, "Key not found or access denied"), nil
	}
	packet, err := pgptoken.KeyFromToken(key)
	info, err := signrpm.SignRpmStream(request.Body, packet, nil)
	if err != nil {
		if err == io.ErrUnexpectedEOF {
			return StringResponse(400, "unexpected EOF"), nil
		} else if _, ok := err.(net.Error); ok {
			return StringResponse(400, "error reading from socket"), nil
		} else {
			fmt.Fprintf(os.Stderr, "Error signing rpm: %s\n", err)
			return ErrorResponse(500), nil
		}
	}
	info.LogTo(os.Stderr)
	var buf bytes.Buffer
	info.Dump(&buf)
	return StringResponse(200, string(buf.Bytes())), nil
}
