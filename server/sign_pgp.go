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
	"io"
	"net/http"
	"os"
	"strconv"

	"gerrit-pdt.unx.sas.com/tools/relic.git/config"
)

func (s *Server) signPgp(keyConf *config.KeyConfig, request *http.Request, filename string, writer http.ResponseWriter) (Response, error) {
	cmdline := []string{
		os.Args[0],
		"sign-pgp",
		"--config", s.Config.Path(),
		"--key", keyConf.Name(),
	}
	if n, _ := strconv.Atoi(request.URL.Query().Get("armor")); n != 0 {
		cmdline = append(cmdline, "--armor")
	}
	var stdoutStream io.Writer
	var counter *responseCounter
	if n, _ := strconv.Atoi(request.URL.Query().Get("clearsign")); n != 0 {
		// Normally it's best to spool the signature to a buffer to handle any
		// errors that occur while signing because signatures are small, but
		// clearsign repeats its original input so it makes more sense to
		// stream it.
		counter = &responseCounter{writer: writer}
		stdoutStream = counter
		writer.Header().Add("Trailer", "X-Status")
		cmdline = append(cmdline, "--clearsign")
	} else {
		cmdline = append(cmdline, "--detach-sign")
	}
	stdoutBytes, response, err := s.invokeCommand(request, request.Body, stdoutStream, "", false, keyConf.GetTimeout(), cmdline)
	if response != nil || err != nil {
		if counter.Count() == 0 {
			// No headers sent yet so just handle this the normal way
			return response, err
		}
		// Headers were sent so do the usual logging stuff but send the error
		// status as a trailer. The error text will also get appended to the
		// output stream as a last resort in case the client didn't notice.
		if response == nil {
			response = s.LogError(request, err, nil)
		}
		status := 500
		if br, ok := response.(*bytesResponse); ok {
			writer.Write(br.Body)
			status = br.StatusCode
		}
		writer.Header().Set("X-Status", fmt.Sprintf("%d", status))
		return nil, nil
	}
	s.Logf("Signed PGP message: filename=%s key=%s client=%s ip=%s", filename, keyConf.Name(), GetClientName(request), GetClientIP(request))
	if stdoutStream == nil {
		return BytesResponse(stdoutBytes, "application/pgp-signature"), nil
	} else {
		writer.Header().Set("X-Status", "200")
		return nil, nil
	}
}

type responseCounter struct {
	writer io.Writer
	sent   uint64
}

func (rc *responseCounter) Write(d []byte) (int, error) {
	n, err := rc.writer.Write(d)
	rc.sent += uint64(n)
	return n, err
}

func (rc *responseCounter) Count() uint64 {
	if rc != nil {
		return rc.sent
	} else {
		return 0
	}
}
