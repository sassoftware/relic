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

func (s *Server) serveSign(request *http.Request, writer http.ResponseWriter) (res Response, err error) {
	if request.Method != "POST" {
		return ErrorResponse(http.StatusMethodNotAllowed), nil
	}
	query := request.URL.Query()
	keyName := query.Get("key")
	if keyName == "" {
		return StringResponse(http.StatusBadRequest, "'key' query parameter is required"), nil
	}
	sigType := query.Get("sigtype")
	filename := query.Get("filename")
	exten := path.Ext(filename)
	if sigType == "" && (filename == "" || exten == "") {
		return StringResponse(http.StatusBadRequest, "'filename' query parameter is required and must have a known extension"), nil
	}
	keyConf := s.CheckKeyAccess(request, keyName)
	if keyConf == nil {
		s.Logr(request, "access denied to key %s\n", keyName)
		return AccessDeniedResponse, nil
	}
	if keyConf.Tool != "" {
		return s.signWithTool(keyConf, request, filename, writer)
	} else if keyConf.Token == "" {
		return nil, fmt.Errorf("Key %s needs a tool or token setting", keyName)
	}
	switch sigType {
	case "pgp":
		return s.signPgp(keyConf, request, filename)
	case "rpm":
		return s.signRpm(keyConf, request)
	case "deb":
		return s.signDeb(keyConf, request, filename)
	case "jar-manifest":
		return s.signJar(keyConf, request, filename)
	case "pe-coff":
		return s.signPeCoff(keyConf, request, filename)
	case "msi-tar":
		return s.signMsi(keyConf, request, filename)
	case "":
		// look at filename
	default:
		s.Logr(request, "error: unknown sigtype: sigtype=%s key=%s", sigType, keyName)
		return StringResponse(http.StatusBadRequest, "unknown sigtype"), nil
	}
	switch exten {
	case ".rpm":
		return s.signRpm(keyConf, request)
	case ".deb":
		return s.signDeb(keyConf, request, filename)
	default:
		s.Logr(request, "error: unknown filetype: filename=%s key=%s", filename, keyName)
		return StringResponse(http.StatusBadRequest, "unknown filetype for key"), nil
	}
}
