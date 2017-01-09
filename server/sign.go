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
	"fmt"
	"net/http"
	"path"
)

func (s *Server) serveSign(request *http.Request) (res Response, err error) {
	if request.Method != "POST" {
		return ErrorResponse(http.StatusMethodNotAllowed), nil
	}
	query := request.URL.Query()
	keyName := query.Get("key")
	if keyName == "" {
		return StringResponse(http.StatusBadRequest, "'key' query parameter is required"), nil
	}
	filename := query.Get("filename")
	exten := path.Ext(filename)
	if filename == "" || exten == "" {
		return StringResponse(http.StatusBadRequest, "'filename' query parameter is required and must have a known extension"), nil
	}
	keyConf := s.CheckKeyAccess(request, keyName)
	if keyConf == nil {
		s.Logf("Access denied: client %s (%s), key %s\n", GetClientName(request), GetClientIP(request), keyName)
		return AccessDeniedResponse, nil
	}
	if keyConf.Tool != "" {
		return s.signWithTool(keyConf, request, filename)
	} else if keyConf.Token == "" {
		return nil, fmt.Errorf("Key %s needs a tool or token setting", keyName)
	} else if exten == ".rpm" {
		return s.signRpm(keyConf, request)
	} else {
		s.Logf("error: unknown filetype: filename=%s key=%s client=%s ip=%s", filename, keyName, GetClientName(request), GetClientIP(request))
		return StringResponse(http.StatusBadRequest, "unknown filetype for key"), nil
	}
}
