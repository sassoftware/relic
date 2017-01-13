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
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path"

	"gerrit-pdt.unx.sas.com/tools/relic.git/config"
)

func (s *Server) signWithTool(keyConf *config.KeyConfig, request *http.Request, filename string) (Response, error) {
	cleanName := "target" + path.Ext(filename)
	cmdline, err := keyConf.GetToolCmd(cleanName)
	if err != nil {
		return nil, err
	}
	scratchDir, err := ioutil.TempDir("", "relic-")
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			os.RemoveAll(scratchDir)
		}
	}()
	scratchPath := path.Join(scratchDir, cleanName)
	size, err := spoolFile(request, scratchPath)
	if err == io.ErrUnexpectedEOF {
		s.Logf("client hung up while spooling input file: client=%s ip=%s", GetClientName(request), GetClientIP(request))
		return ErrorResponse(http.StatusBadRequest), nil
	} else if err != nil {
		return nil, err
	}
	_, response, err := s.invokeCommand(request, nil, scratchDir, true, keyConf.GetTimeout(), cmdline)
	if response != nil || err != nil {
		return response, err
	}
	s.Logf("Signed package: filename=%s key=%s size=%d client=%s ip=%s", filename, keyConf.Name(), size, GetClientName(request), GetClientIP(request))
	return FileResponse(scratchPath, true)
}

func spoolFile(request *http.Request, path string) (int64, error) {
	file, err := os.Create(path)
	if err != nil {
		return 0, err
	}
	defer file.Close()
	return io.Copy(file, request.Body)
}
