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

	"gerrit-pdt.unx.sas.com/tools/relic.git/config"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/signrpm"
)

func (s *Server) signRpm(keyConf *config.KeyConfig, request *http.Request) (Response, error) {
	cmdline := []string{
		os.Args[0],
		"sign-rpm",
		"--config", s.Config.Path(),
		"--key", keyConf.Name(),
		"--file", "-",
		"--patch",
	}
	stdout, response, err := s.invokeCommand(request, request.Body, nil, "", false, keyConf.GetTimeout(), cmdline)
	if response != nil || err != nil {
		return response, err
	}
	endOfJson := bytes.IndexByte(stdout, 0)
	if endOfJson < 0 {
		return nil, errors.New("Did not find null terminator in sign-rpm output")
	}
	jinfo, err := signrpm.LoadJson(stdout[:endOfJson])
	if err != nil {
		return nil, err
	}
	jinfo.ClientName = GetClientName(request)
	jinfo.ClientIP = GetClientIP(request)
	s.Logf("Signed package: nevra=%s key=%s fp=%s md5=%s sha1=%s client=%s ip=%s",
		jinfo.Nevra, keyConf.Name(), jinfo.Fingerprint, jinfo.Md5, jinfo.Sha1, jinfo.ClientName, jinfo.ClientIP)
	var buf bytes.Buffer
	jinfo.Dump(&buf)
	buf.Write(stdout[endOfJson:])
	return BytesResponse(buf.Bytes(), "application/x-binary-patch"), nil
}
