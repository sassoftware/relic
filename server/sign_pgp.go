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
	"strconv"

	"gerrit-pdt.unx.sas.com/tools/relic.git/config"
)

func (s *Server) signPgp(keyConf *config.KeyConfig, request *http.Request, filename string) (Response, error) {
	cmdline := []string{
		os.Args[0],
		"sign-pgp",
		"--detach-sign",
		"--config", s.Config.Path(),
		"--key", keyConf.Name(),
	}
	if n, _ := strconv.Atoi(request.URL.Query().Get("armor")); n != 0 {
		cmdline = append(cmdline, "--armor")
	}
	stdout, response, err := s.invokeCommand(request, request.Body, "", false, keyConf.GetTimeout(), cmdline)
	if response != nil || err != nil {
		return response, err
	}
	s.Logf("Signed PGP message: filename=%s key=%s client=%s ip=%s", filename, keyConf.Name(), GetClientName(request), GetClientIP(request))
	return BytesResponse(stdout, "application/pgp-signature"), nil
}
