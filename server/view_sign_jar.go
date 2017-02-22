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
	"io/ioutil"
	"net/http"
	"os"

	"gerrit-pdt.unx.sas.com/tools/relic.git/config"
)

func (s *Server) signJar(keyConf *config.KeyConfig, request *http.Request) (Response, error) {
	cmdline := []string{
		os.Args[0],
		"sign-jar-manifest",
		"--config", s.Config.Path(),
		"--key", keyConf.Name(),
		"--file", "-",
		"--output", "-",
	}
	cmdline = appendDigest(cmdline, request)
	manifest, err := ioutil.ReadAll(request.Body)
	if err != nil {
		return nil, err
	}
	stdin := bytes.NewReader(manifest)
	stdout, response, err := s.invokeCommand(request, stdin, "", false, keyConf.GetTimeout(), cmdline)
	if response != nil || err != nil {
		return response, err
	}
	filename := request.URL.Query().Get("filename")
	s.Logr(request, "signed jar manifest: filename=%s key=%s size=%d", filename, keyConf.Name(), stdin.Size())
	return BytesResponse(stdout, "application/pkcs7-mime"), nil
}
