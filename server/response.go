//
// Copyright (c) SAS Institute Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/sassoftware/relic/v7/internal/httperror"
	"github.com/sassoftware/relic/v7/token"
)

type Response interface {
	Headers() map[string]string
	Status() int
	Bytes() []byte
}

type bytesResponse struct {
	StatusCode  int
	ContentType string
	Body        []byte
}

func (r bytesResponse) Bytes() []byte {
	return r.Body
}

func (r bytesResponse) Status() int {
	return r.StatusCode
}

func (r bytesResponse) Headers() map[string]string {
	return map[string]string{
		"Content-Length": fmt.Sprintf("%d", len(r.Body)),
		"Content-Type":   r.ContentType,
	}
}

func BytesResponse(body []byte, contentType string) Response {
	return &bytesResponse{
		StatusCode:  http.StatusOK,
		ContentType: contentType,
		Body:        body,
	}
}

func StringResponse(statusCode int, body string) Response {
	return &bytesResponse{
		StatusCode:  statusCode,
		ContentType: "text/plain",
		Body:        []byte(body + "\r\n"),
	}
}

func ErrorResponse(statusCode int) Response {
	return &bytesResponse{
		StatusCode:  statusCode,
		ContentType: "text/plain",
		Body:        []byte(http.StatusText(statusCode) + "\r\n"),
	}
}

var AccessDeniedResponse Response = &bytesResponse{
	StatusCode:  http.StatusForbidden,
	ContentType: "text/plain",
	Body:        []byte("Access denied\r\n"),
}

func JSONResponse(data interface{}) (Response, error) {
	blob, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	return &bytesResponse{
		StatusCode:  http.StatusOK,
		ContentType: "application/json",
		Body:        blob,
	}, nil
}

func writeResponse(writer http.ResponseWriter, response Response) {
	for k, v := range response.Headers() {
		writer.Header().Set(k, v)
	}
	writer.WriteHeader(response.Status())
	_, _ = writer.Write(response.Bytes())
}

func errToProblem(err error) http.Handler {
	if e := new(token.KeyUsageError); errors.As(err, e) {
		return httperror.Problem{
			Status: http.StatusBadRequest,
			Type:   httperror.ProblemKeyUsage,
			Title:  "Incorrect Key Usage",
			Detail: e.Error(),
		}
	}
	return nil
}
