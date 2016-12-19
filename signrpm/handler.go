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

package signrpm

import (
	"bytes"
	"io"
	"net"
	"net/http"

	"gerrit-pdt.unx.sas.com/tools/relic.git/p11token"
	"gerrit-pdt.unx.sas.com/tools/relic.git/pgptoken"
	"gerrit-pdt.unx.sas.com/tools/relic.git/server"
)

type signRpmHandler struct {
	server *server.Server
	keyMap map[string]*p11token.Key
}

func (h *signRpmHandler) Handle(request *http.Request) (server.Response, error) {
	if request.Method != "POST" {
		return server.ErrorResponse(http.StatusMethodNotAllowed), nil
	}
	query := request.URL.Query()
	keyName := query.Get("key")
	if keyName == "" {
		return server.StringResponse(http.StatusBadRequest, "'key' query parameter is required"), nil
	}
	clientName := server.GetClientName(request)
	if !h.server.CheckKeyAccess(request, keyName) {
		h.server.Logf("Access denied: client %s (%s), key %s\n", clientName, server.GetClientIP(request), keyName)
		return server.AccessDeniedResponse, nil
	}
	key := h.keyMap[keyName]
	packet, err := pgptoken.KeyFromToken(key)
	info, err := SignRpmStream(request.Body, packet, nil)
	if err != nil {
		if err == io.ErrUnexpectedEOF {
			return server.StringResponse(400, "unexpected EOF"), nil
		} else if _, ok := err.(net.Error); ok {
			return server.StringResponse(400, "error reading from socket"), nil
		} else {
			h.server.Logf("Error signing rpm: %s\n", err)
			return server.ErrorResponse(500), nil
		}
	}
	info.KeyName = keyName
	info.ClientName = clientName
	info.ClientIP = server.GetClientIP(request)
	h.server.Logf("%s", info)
	var buf bytes.Buffer
	info.Dump(&buf)
	return server.StringResponse(200, string(buf.Bytes())), nil
}

func AddSignRpmHandler(server *server.Server, keyMap map[string]*p11token.Key) {
	server.Handlers["/sign_rpm"] = &signRpmHandler{server: server, keyMap: keyMap}
}
