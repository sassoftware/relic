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
	"encoding/json"
	"fmt"
	"net/http"
)

type Response interface {
	Write(http.ResponseWriter)
	Close()
}

type bytesResponse struct {
	StatusCode  int
	ContentType string
	Headers     map[string]string
	Body        []byte
}

func (r *bytesResponse) Write(writer http.ResponseWriter) {
	writer.Header().Set("Content-Length", fmt.Sprintf("%d", len(r.Body)))
	writer.Header().Set("Content-Type", r.ContentType)
	writer.WriteHeader(r.StatusCode)
	writer.Write(r.Body)
}

func (r *bytesResponse) Close() {}

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

func JsonResponse(data interface{}) (Response, error) {
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
