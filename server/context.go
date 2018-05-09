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
	"net/http"
	"strings"
)

type ctxKey int

const (
	ctxClientName ctxKey = iota
	ctxRoles
	ctxClientDN
)

func GetClientRoles(request *http.Request) []string {
	roles := request.Context().Value(ctxRoles)
	if roles == nil {
		return nil
	}
	return roles.([]string)
}

func GetClientName(request *http.Request) string {
	name := request.Context().Value(ctxClientName)
	if name == nil {
		return ""
	}
	return name.(string)
}

func GetClientDN(request *http.Request) string {
	name := request.Context().Value(ctxClientDN)
	if name == nil {
		return ""
	}
	return name.(string)
}

func GetClientIP(request *http.Request) string {
	address := request.RemoteAddr
	colon := strings.LastIndex(address, ":")
	if colon < 0 {
		return address
	}
	address = address[:colon]
	if address[0] == '[' && address[len(address)-1] == ']' {
		address = address[1 : len(address)-1]
	}
	return address
}
