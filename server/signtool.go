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
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path"
	"strings"
)

func (s *Server) serveSignTool(request *http.Request) (res Response, err error) {
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
	if exten == "" {
		return StringResponse(http.StatusBadRequest, "'filename' query parameter is required"), nil
	}
	clientName := GetClientName(request)
	if !s.CheckKeyAccess(request, keyName) {
		s.Logf("Access denied: client %s (%s), key %s\n", clientName, GetClientIP(request), keyName)
		return AccessDeniedResponse, nil
	}
	cleanName := "target" + exten
	cmdline, err := s.Config.GetToolCmd(keyName, cleanName)
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
	if err != nil {
		return nil, err
	}
	err = signFile(s, cmdline, scratchDir)
	if err != nil {
		return nil, err
	}
	s.Logf("Signed package: filename=%s key=%s size=%d client=%s ip=%s", filename, keyName, size, clientName, GetClientIP(request))
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

func formatCmdline(cmdline []string) string {
	words := make([]string, len(cmdline))
	for i, word := range cmdline {
		if strings.Index(word, " ") >= 0 {
			word = "\"" + word + "\""
		}
		words[i] = word
	}
	return strings.Join(words, " ")
}

func signFile(server *Server, cmdline []string, scratchDir string) error {
	proc := exec.Command(cmdline[0], cmdline[1:]...)
	proc.Dir = scratchDir
	output, err := proc.CombinedOutput()
	if err != nil {
		server.Logf("Error invoking signing tool: %s\nCommand: %s\nOutput:\n%s\n\n", err, formatCmdline(cmdline), output)
		return errors.New("Error invoking signing tool")
	}
	return nil
}
