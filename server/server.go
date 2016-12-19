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
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"runtime"
	"strings"

	"gerrit-pdt.unx.sas.com/tools/relic.git/config"
	"gerrit-pdt.unx.sas.com/tools/relic.git/p11token"
)

type Handler struct {
	Config *config.Config
	KeyMap map[string]*p11token.Key
}

type ctxKey int

const (
	ctxClientName ctxKey = iota
	ctxRoles
)

func (handler *Handler) callHandler(request *http.Request) (response Response, err error) {
	defer func() {
		if caught := recover(); caught != nil {
			const size = 64 << 10
			buf := make([]byte, size)
			buf = buf[:runtime.Stack(buf, false)]
			handler.Logf("Unhandled exception from client %s: %s\n%s\n", remoteIP(request), caught, buf)
			response = ErrorResponse(http.StatusInternalServerError)
			err = nil
		}
	}()
	ctx := request.Context()
	ctx, errResponse := handler.getUserRoles(ctx, request)
	if errResponse != nil {
		return errResponse, nil
	}
	request = request.WithContext(ctx)
	switch request.URL.Path {
	case "/":
		return handler.serveHome(request)
	case "/sign_rpm":
		return handler.serveSignRpm(request)
	default:
		return ErrorResponse(http.StatusNotFound), nil
	}
}

func (handler *Handler) getUserRoles(ctx context.Context, request *http.Request) (context.Context, Response) {
	if request.TLS == nil {
		return nil, StringResponse(http.StatusBadRequest, "Retry request using TLS")
	}
	if len(request.TLS.PeerCertificates) == 0 {
		return nil, StringResponse(http.StatusBadRequest, "Invalid client certificate")
	}
	cert := request.TLS.PeerCertificates[0]
	digest := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	encoded := hex.EncodeToString(digest[:])
	client, ok := handler.Config.Clients[encoded]
	if !ok {
		handler.Logf("Denied access to unknown client %s with fingerprint %s\n", remoteIP(request), encoded)
		return nil, AccessDeniedResponse
	}
	ctx = context.WithValue(ctx, ctxClientName, client.Nickname)
	ctx = context.WithValue(ctx, ctxRoles, client.Roles)
	return ctx, nil
}

func (handler *Handler) CheckKeyAccess(ctx context.Context, keyName string) bool {
	if handler.Config.Keys == nil {
		return false
	}
	key, ok := handler.Config.Keys[keyName]
	if !ok {
		return false
	}
	clientRoles, ok := ctx.Value(ctxRoles).([]string)
	if !ok {
		return false
	}
	for _, keyRole := range key.Roles {
		for _, clientRole := range clientRoles {
			if keyRole == clientRole {
				return true
			}
		}
	}
	return false
}

func (handler *Handler) Logf(format string, args ...interface{}) {
	log.Printf(format, args...)
}

func remoteIP(request *http.Request) string {
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

func (handler *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	response, err := handler.callHandler(request)
	if err != nil {
		handler.Logf("Unhandled exception from client %s: %s\n", remoteIP(request), err)
		response = ErrorResponse(http.StatusInternalServerError)
	}
	response.Write(writer)
}

func parseCertChain(path string) ([][]byte, error) {
	pemData, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("unable to read certificate chain: %s", err)
	}
	certs := make([][]byte, 0)
	for {
		var block *pem.Block
		block, pemData = pem.Decode(pemData)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			certs = append(certs, block.Bytes)
		} else {
			return nil, fmt.Errorf("Found unexpected %s block in certificate chain", block.Type)
		}
	}
	return certs, nil
}

func makeTlsConfig(conf *config.Config) (*tls.Config, error) {
	tlscert, err := tls.LoadX509KeyPair(conf.Server.CertFile, conf.Server.KeyFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates:             []tls.Certificate{tlscert},
		PreferServerCipherSuites: true,
		SessionTicketsDisabled:   true,
		ClientAuth:               tls.RequireAnyClientCert,
		MinVersion:               tls.VersionTLS12,
	}, nil
}

func Serve(conf *config.Config, keyMap map[string]*p11token.Key) error {
	handler := &Handler{
		Config: conf,
		KeyMap: keyMap,
	}
	tconf, err := makeTlsConfig(conf)
	if err != nil {
		return err
	}
	listener, err := tls.Listen("tcp", conf.Server.Listen, tconf)
	if err != nil {
		return err
	}
	httpServer := &http.Server{Handler: handler}
	return httpServer.Serve(listener)
}
