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
	"log"
	"net/http"
	"strings"
)

// Set the logger where the server will write its messages
func (s *Server) SetLogger(logger *log.Logger) {
	s.ErrorLog = logger
	s.DiskMgr.SetLogger(logger)
}

// Log a general message
func (s *Server) Logf(format string, args ...interface{}) {
	s.ErrorLog.Output(2, fmt.Sprintf(format, args...))
}

// Log a message associated with an ongoing request
func (s *Server) Logr(request *http.Request, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	msg2 := fmt.Sprintf("[%s \"%s\"] %s", GetClientIP(request), GetClientName(request), msg)
	s.ErrorLog.Output(2, msg2)
}

// Log an unhandled error with optional traceback
func (s *Server) LogError(request *http.Request, err interface{}, traceback []byte) Response {
	msg := ""
	if len(traceback) != 0 {
		msg = "\n " + strings.Replace(string(traceback), "\n", "\n ", -1)
	}
	s.Logr(request, "unhandled exception: %s%s\n", err, msg)
	return ErrorResponse(http.StatusInternalServerError)
}

// Wraps a http.ResponseWriter and writes an access log entry on completion
type loggingWriter struct {
	http.ResponseWriter
	s      *Server
	r      *http.Request
	wrote  bool
	length int64
	status int
}

func (lw *loggingWriter) WriteHeader(status int) {
	lw.wrote = true
	lw.status = status
	lw.ResponseWriter.WriteHeader(status)
}

func (lw *loggingWriter) Write(d []byte) (int, error) {
	if !lw.wrote {
		lw.WriteHeader(http.StatusOK)
	}
	n, err := lw.ResponseWriter.Write(d)
	lw.length += int64(n)
	return n, err
}

func (lw *loggingWriter) CloseNotify() <-chan bool {
	return lw.ResponseWriter.(http.CloseNotifier).CloseNotify()
}

func (lw *loggingWriter) Close() {
	path := lw.r.URL.Path
	if path == "/health" {
		// don't log health check spam
		return
	}
	ua := lw.r.Header.Get("User-Agent")
	if ua == "" {
		ua = "-"
	}
	lw.s.Logr(lw.r, "%s \"%s\" %d %d %s", lw.r.Method, lw.r.URL, lw.status, lw.length, ua)
}
