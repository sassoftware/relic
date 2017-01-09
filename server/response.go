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
	"io"
	"log"
	"net/http"
	"os"
	"path"
)

type Response interface {
	Write(http.ResponseWriter)
	Close()
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

func (response *stringResponse) Close() {}

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

type fileResponse struct {
	name      string
	file      *os.File
	size      int64
	deleteDir bool
}

func FileResponse(path string, deleteDir bool) (*fileResponse, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	stat, err := f.Stat()
	if err != nil {
		return nil, err
	}
	return &fileResponse{
		name:      path,
		file:      f,
		size:      stat.Size(),
		deleteDir: deleteDir,
	}, nil
}

func (r *fileResponse) Write(writer http.ResponseWriter) {
	writer.Header().Set("Content-Type", "application/octet-stream")
	writer.Header().Set("Content-Length", fmt.Sprintf("%d", r.size))
	writer.WriteHeader(http.StatusOK)
	io.Copy(writer, r.file)
}

func (r *fileResponse) Close() {
	if r.file != nil {
		r.file.Close()
		r.file = nil
	}
	if r.deleteDir {
		dir := path.Dir(r.name)
		err := os.RemoveAll(dir)
		if err != nil && !os.IsNotExist(err) {
			log.Printf("error: failed to cleanup scratch directory %s: %s", dir, err)
		}
	}
}

type bytesResponse struct {
	body        []byte
	contentType string
}

func BytesResponse(body []byte, contentType string) Response {
	return &bytesResponse{body: body, contentType: contentType}
}

func JsonResponse(data interface{}) (Response, error) {
	blob, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	return &bytesResponse{body: blob, contentType: "application/json"}, nil
}

func (r *bytesResponse) Write(writer http.ResponseWriter) {
	writer.Header().Set("Content-Type", r.contentType)
	writer.Header().Set("Content-Length", fmt.Sprintf("%d", len(r.body)))
	writer.WriteHeader(http.StatusOK)
	writer.Write(r.body)
}

func (response *bytesResponse) Close() {}
