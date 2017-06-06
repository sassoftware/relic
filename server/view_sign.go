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
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/sassoftware/relic/lib/audit"
	"github.com/sassoftware/relic/lib/procutil"
	"github.com/sassoftware/relic/signers"
)

func (s *Server) serveSign(request *http.Request, writer http.ResponseWriter) (res Response, err error) {
	if request.Method != "POST" {
		return ErrorResponse(http.StatusMethodNotAllowed), nil
	}
	query := request.URL.Query()
	keyName := query.Get("key")
	if keyName == "" {
		return StringResponse(http.StatusBadRequest, "'key' query parameter is required"), nil
	}
	filename := query.Get("filename")
	if filename == "" {
		return StringResponse(http.StatusBadRequest, "'filename' query parameter is required"), nil
	}
	sigType := query.Get("sigtype")
	keyConf := s.CheckKeyAccess(request, keyName)
	if keyConf == nil {
		s.Logr(request, "access denied to key %s\n", keyName)
		return AccessDeniedResponse, nil
	}
	if keyConf.Token == "" {
		return nil, fmt.Errorf("Key %s needs a token setting", keyName)
	}
	mod := signers.ByName(sigType)
	if mod == nil {
		s.Logr(request, "error: unknown sigtype: sigtype=%s key=%s", sigType, keyName)
		return StringResponse(http.StatusBadRequest, "unknown sigtype"), nil
	}
	cmdline := []string{
		os.Args[0],
		"sign",
		"--config", s.Config.Path(),
		"--server",
		"--key", keyConf.Name(),
		"--sig-type", mod.Name,
	}
	if digest := request.URL.Query().Get("digest"); digest != "" {
		cmdline = append(cmdline, "--digest", digest)
	}
	flags := mod.QueryToCmdline(request.URL.Query())
	cmdline = append(cmdline, flags...)
	// build subproc environment
	cmd := procutil.CommandContext(request.Context(), cmdline, keyConf.GetTimeout())
	infd, err := cmd.AttachInput(request.Body)
	if err != nil {
		return nil, err
	}
	cmd.Proc.Args = append(cmd.Proc.Args, fmt.Sprintf("--file=/dev/fd/%d", infd))
	outfd, err := cmd.AttachOutput()
	if err != nil {
		return nil, err
	}
	cmd.Proc.Args = append(cmd.Proc.Args, fmt.Sprintf("--output=/dev/fd/%d", outfd))
	auditfd, err := cmd.AttachOutput()
	if err != nil {
		return nil, err
	}
	env := os.Environ()
	env = audit.PutAuditFd(env, auditfd)
	env = audit.PutEnv(env, "client.ip", GetClientIP(request))
	env = audit.PutEnv(env, "client.name", GetClientName(request))
	env = audit.PutEnv(env, "client.filename", filename)
	cmd.Proc.Env = env
	// execute
	if err := cmd.Run(); err != nil {
		return s.showProcError(request, cmd, keyConf.GetTimeout(), err)
	}
	// gather results
	result := cmd.Pipes[outfd]
	if len(result) == 0 {
		return nil, errors.New("empty result")
	}
	attrs, err := audit.Parse(cmd.Pipes[auditfd])
	if err != nil {
		return nil, err
	}
	var extra string
	if mod.FormatLog != nil {
		extra = mod.FormatLog(attrs)
	}
	if extra != "" {
		extra = " " + extra
	}
	s.Logr(request, "Signed package: filename=%s key=%s%s", filename, keyConf.Name(), extra)
	return BytesResponse(result, attrs.GetMimeType()), nil
}

func (s *Server) showProcError(request *http.Request, cmd *procutil.Command, timeout time.Duration, err error) (Response, error) {
	switch err {
	case context.DeadlineExceeded:
		s.Logr(request, "error: command timed out after %d seconds\nCommand: %s\nOutput:\n%s\n\n",
			timeout/time.Second, cmd.FormatCmdline(), cmd.Output)
		return StringResponse(http.StatusGatewayTimeout, "Signing command timed out"), nil
	case context.Canceled:
		s.Logr(request, "client hung up during signing operation")
		return StringResponse(http.StatusGatewayTimeout, "Signing command timed out"), nil
	}
	s.Logr(request, "error: invoking signing tool: %s\nCommand: %s\nOutput:\n%s\n\n", err, cmd.FormatCmdline(), cmd.Output)
	switch {
	case strings.Contains(cmd.Output, "no certificate of type"):
		return StringResponse(http.StatusBadRequest, "key does not support signatures of this type"), nil
	default:
		return ErrorResponse(http.StatusInternalServerError), nil
	}
}
