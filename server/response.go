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
	"net/http"
)

type Response interface {
	Write(http.ResponseWriter)
}

type stringResponse struct {
	StatusCode int
	Body       string
}

func (response *stringResponse) Write(writer http.ResponseWriter) {
	body := []byte(response.Body)
	writer.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
	writer.Header().Set("Content-Type", "text/plain")
	writer.WriteHeader(response.StatusCode)
	writer.Write(body)
}

func StringResponse(statusCode int, body string) Response {
	return &stringResponse{
		StatusCode: statusCode,
		Body:       body + "\r\n",
	}
}

func ErrorResponse(statusCode int) Response {
	return &stringResponse{
		StatusCode: statusCode,
		Body:       http.StatusText(statusCode) + "\r\n",
	}
}

var AccessDeniedResponse Response = &stringResponse{
	StatusCode: http.StatusForbidden,
	Body:       "Access denied\r\n",
}
