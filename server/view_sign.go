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
	"errors"
	"fmt"
	"net/http"
	"os"

	"gerrit-pdt.unx.sas.com/tools/relic.git/signers"
)

func (s *Server) serveSign(request *http.Request, writer http.ResponseWriter) (res Response, err error) {
	if request.Method != "POST" {
		return ErrorResponse(http.StatusMethodNotAllowed), nil
	}
	query := request.URL.Query()
	keyName := query.Get("key")
	if keyName == "" {
		return StringResponse(http.StatusBadRequest, "'key' query parameter is required"), nil
	}
	filename := query.Get("filename")
	if filename == "" {
		return StringResponse(http.StatusBadRequest, "'filename' query parameter is required and must have a known extension"), nil
	}
	sigType := query.Get("sigtype")
	keyConf := s.CheckKeyAccess(request, keyName)
	if keyConf == nil {
		s.Logr(request, "access denied to key %s\n", keyName)
		return AccessDeniedResponse, nil
	}
	if keyConf.Tool != "" {
		return s.signWithTool(keyConf, request, writer)
	} else if keyConf.Token == "" {
		return nil, fmt.Errorf("Key %s needs a tool or token setting", keyName)
	}
	mod := signers.ByName(sigType)
	if mod == nil {
		s.Logr(request, "error: unknown sigtype: sigtype=%s key=%s", sigType, keyName)
		return StringResponse(http.StatusBadRequest, "unknown sigtype"), nil
	}
	cmdline := []string{
		os.Args[0],
		"sign",
		"--config", s.Config.Path(),
		"--key", keyConf.Name(),
		"--sig-type", mod.Name,
		"--file", "-",
		"--output", "-",
		"--server",
	}
	if digest := request.URL.Query().Get("digest"); digest != "" {
		cmdline = append(cmdline, "--digest", digest)
	}
	flags := mod.QueryToCmdline(request.URL.Query())
	cmdline = append(cmdline, flags...)
	fmt.Printf("%#v\n", cmdline)
	stdout, attrs, response, err := s.invokeCommand(request, request.Body, "", false, keyConf.GetTimeout(), cmdline)
	if response != nil || err != nil {
		return response, err
	}
	if attrs == nil {
		return nil, errors.New("missing audit info")
	}
	var extra string
	if mod.FormatLog != nil {
		extra = mod.FormatLog(attrs)
	}
	if extra != "" {
		extra = " " + extra
	}
	s.Logr(request, "Signed package: filename=%s key=%s%s", filename, keyConf.Name(), extra)
	return BytesResponse(stdout, attrs.GetMimeType()), nil
}
