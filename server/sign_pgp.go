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
	"os"
	"strconv"

	"gerrit-pdt.unx.sas.com/tools/relic.git/config"
)

func (s *Server) signPgp(keyConf *config.KeyConfig, request *http.Request, filename string) (Response, error) {
	cmdline := []string{
		os.Args[0],
		"sign-pgp",
		"--config", s.Config.Path(),
		"--key", keyConf.Name(),
	}
	if n, _ := strconv.Atoi(request.URL.Query().Get("armor")); n != 0 {
		cmdline = append(cmdline, "--armor")
	}
	pgp := request.URL.Query().Get("pgp")
	if pgp == "mini-clear" {
		cmdline = append(cmdline, "--mini-clear")
	} else if pgp == "clearsign" {
		cmdline = append(cmdline, "--clearsign")
		// clearsign passes its input through to the output and stdout is
		// buffered, so check that the request isn't too big
		if request.ContentLength < 0 {
			s.Logf("Refused signature because content-length is missing: filename=%s key=%s client=%s ip=%s", filename, keyConf.Name(), GetClientName(request), GetClientIP(request))
			return StringResponse(http.StatusLengthRequired, "Length Required\n\nContent-Length is required when using clearsign"), nil
		} else if request.ContentLength > s.Config.Server.MaxDocSize {
			s.Logf("Refused signature because content-length exceeds limit: filename=%s size=%d key=%s client=%s ip=%s", filename, request.ContentLength, keyConf.Name(), GetClientName(request), GetClientIP(request))
			return StringResponse(http.StatusRequestEntityTooLarge, fmt.Sprintf("Request Entity Too Large\n\nRequest exceeds the configured maximum Content-Length of %d bytes", s.Config.Server.MaxDocSize)), nil
		}
	} else {
		cmdline = append(cmdline, "--detach-sign")
	}
	stdout, response, err := s.invokeCommand(request, request.Body, "", false, keyConf.GetTimeout(), cmdline)
	if response != nil || err != nil {
		return response, err
	}
	s.Logf("Signed PGP message: filename=%s key=%s client=%s ip=%s", filename, keyConf.Name(), GetClientName(request), GetClientIP(request))
	return BytesResponse(stdout, "application/pgp-signature"), nil
}
