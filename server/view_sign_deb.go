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
	"net/http"
	"os"

	"gerrit-pdt.unx.sas.com/tools/relic.git/config"
)

func (s *Server) signDeb(keyConf *config.KeyConfig, request *http.Request, filename string) (Response, error) {
	cmdline := []string{
		os.Args[0],
		"sign-deb",
		"--config", s.Config.Path(),
		"--key", keyConf.Name(),
		"--file", "-",
		"--patch",
	}
	if role := request.URL.Query().Get("deb-role"); role != "" {
		cmdline = append(cmdline, "--role", role)
	}
	stdout, response, err := s.invokeCommand(request, request.Body, "", false, keyConf.GetTimeout(), cmdline)
	if response != nil || err != nil {
		return response, err
	}
	s.Logr(request, "Signed package: filename=%s key=%s", filename, keyConf.Name())
	return BytesResponse(stdout, "application/x-binary-patch"), nil
}
