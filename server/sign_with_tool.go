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
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path"

	"gerrit-pdt.unx.sas.com/tools/relic.git/config"
	"gerrit-pdt.unx.sas.com/tools/relic.git/server/diskmgr"
)

func (s *Server) allocScratch(keyConf *config.KeyConfig, request *http.Request, filename string) (diskmgr.CancelFunc, Response, error) {
	if request.ContentLength < 0 {
		s.Logf("Refused signature because content-length is missing: filename=%s key=%s client=%s ip=%s", filename, keyConf.Name(), GetClientName(request), GetClientIP(request))
		return nil, StringResponse(http.StatusLengthRequired, "Length Required\n\nContent-Length is required when using clearsign"), nil
	}
	allocate := uint64(request.ContentLength) * 2
	info := fmt.Sprintf("filename=%s client=%s ip=%s", filename, GetClientName(request), GetClientIP(request))
	cancel, err := s.DiskMgr.Request(request.Context(), allocate, info)
	if err == nil {
		return cancel, nil, nil
	}
	var why string
	status := http.StatusGatewayTimeout
	switch err {
	case diskmgr.ErrTooBig:
		why = "error: request exceeded available scratch space"
		status = http.StatusBadRequest
	case context.Canceled:
		why = "client hung up waiting for available scratch space"
	case context.DeadlineExceeded:
		why = "request timed out waiting for available scratch space"
	default:
		return nil, nil, err
	}
	s.Logf("%s: filename=%s allocation=%d key=%s client=%s ip=%s", why, filename, allocate, keyConf.Name(), GetClientName(request), GetClientIP(request))
	return nil, StringResponse(status, "Disk allocation error\n\n"+why), nil
}

func (s *Server) signWithTool(keyConf *config.KeyConfig, request *http.Request, filename string, writer http.ResponseWriter) (Response, error) {
	cancel, response, err := s.allocScratch(keyConf, request, filename)
	if response != nil || err != nil {
		return response, err
	}
	defer cancel()
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
		if err := os.RemoveAll(scratchDir); err != nil {
			s.Logf("error: failed to clean up scratch directory: %s", err)
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
	_, response, err = s.invokeCommand(request, nil, scratchDir, true, keyConf.GetTimeout(), cmdline)
	if response != nil || err != nil {
		return response, err
	}
	s.Logf("Signed package: filename=%s key=%s size=%d client=%s ip=%s", filename, keyConf.Name(), size, GetClientName(request), GetClientIP(request))
	return nil, sendFile(writer, scratchPath)
}

func spoolFile(request *http.Request, path string) (int64, error) {
	file, err := os.Create(path)
	if err != nil {
		return 0, err
	}
	defer file.Close()
	return io.Copy(file, request.Body)
}

func sendFile(writer http.ResponseWriter, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	stat, err := f.Stat()
	if err != nil {
		return err
	}
	writer.Header().Set("Content-Type", "application/octet-stream")
	writer.Header().Set("Content-Length", fmt.Sprintf("%d", stat.Size()))
	writer.WriteHeader(http.StatusOK)
	io.Copy(writer, f)
	return nil
}
