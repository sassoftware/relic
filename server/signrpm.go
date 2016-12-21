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
	"errors"
	"net/http"
	"os"
	"os/exec"
)

type rpmSignHandler struct {
	server *Server
}

func (h *rpmSignHandler) Handle(request *http.Request) (res Response, err error) {
	if request.Method != "POST" {
		return ErrorResponse(http.StatusMethodNotAllowed), nil
	}
	query := request.URL.Query()
	keyName := query.Get("key")
	if keyName == "" {
		return StringResponse(http.StatusBadRequest, "'key' query parameter is required"), nil
	}
	clientName := GetClientName(request)
	if !h.server.CheckKeyAccess(request, keyName) {
		h.server.Logf("Access denied: client %s (%s), key %s\n", clientName, GetClientIP(request), keyName)
		return AccessDeniedResponse, nil
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	proc := exec.CommandContext(request.Context(), os.Args[0], "--config", h.server.Config.Path(), "sign-rpm", "--key", keyName, "--file", "-", "--json-output")
	proc.Stdin = request.Body
	proc.Stdout = &stdout
	proc.Stderr = &stderr
	err = proc.Run()
	if err != nil {
		h.server.Logf("Error signing RPM: %s\nOutput:\n%s\n\n", err, stderr.Bytes())
		return nil, errors.New("Error signing RPM")
	}
	return StringResponse(http.StatusOK, string(stdout.Bytes())), nil
}

func addSignRpmHandler(server *Server) {
	server.Handlers["/sign_rpm"] = &rpmSignHandler{server: server}
}
