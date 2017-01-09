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

func (s *Server) serveSignRpm(request *http.Request) (res Response, err error) {
	if request.Method != "POST" {
		return ErrorResponse(http.StatusMethodNotAllowed), nil
	}
	query := request.URL.Query()
	keyName := query.Get("key")
	if keyName == "" {
		return StringResponse(http.StatusBadRequest, "'key' query parameter is required"), nil
	}
	format := query.Get("format")
	if format == "" {
		format = "json"
	}
	var formatArg, ctype string
	switch format {
	case "json":
		ctype = "application/json"
		formatArg = "--json-output"
	case "patch":
		ctype = "application/x-binary-patch"
		formatArg = "--patch"
	default:
		return StringResponse(http.StatusBadRequest, "'format' must be one of: json, patch"), nil
	}
	clientName := GetClientName(request)
	if !s.CheckKeyAccess(request, keyName) {
		s.Logf("Access denied: client %s (%s), key %s\n", clientName, GetClientIP(request), keyName)
		return AccessDeniedResponse, nil
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	proc := exec.CommandContext(request.Context(), os.Args[0], "--config", s.Config.Path(), "sign-rpm", "--key", keyName, "--file", "-", formatArg)
	proc.Stdin = request.Body
	proc.Stdout = &stdout
	proc.Stderr = &stderr
	err = proc.Run()
	if err != nil {
		s.Logf("Error signing RPM: %s\nOutput:\n%s\n\n", err, stderr.Bytes())
		return nil, errors.New("Error signing RPM")
	}
	s.Logf("%s", stderr.Bytes())
	return BytesResponse(stdout.Bytes(), ctype), nil
}
