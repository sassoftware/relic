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
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"runtime"

	"gerrit-pdt.unx.sas.com/tools/relic.git/config"
	"gerrit-pdt.unx.sas.com/tools/relic.git/p11token"
)

type Handler struct {
	Config *config.Config
	KeyMap map[string]*p11token.Key
}

func (handler *Handler) callHandler(request *http.Request) (response Response, err error) {
	defer func() {
		if caught := recover(); caught != nil {
			const size = 64 << 10
			buf := make([]byte, size)
			buf = buf[:runtime.Stack(buf, false)]
			fmt.Fprintf(os.Stderr, "Unhandled exception: %s\n%s\n", caught, buf)
			response = ErrorResponse(http.StatusInternalServerError)
			err = nil
		}
	}()
	switch request.URL.Path {
	case "/":
		return handler.serveHome(request)
	case "/sign_rpm":
		return handler.serveSignRpm(request)
	default:
		return ErrorResponse(http.StatusNotFound), nil
	}
}

func (handler *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	response, err := handler.callHandler(request)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unhandled exception: %s\n", err)
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

func makeTlsConfig(conf *config.Config, key *p11token.Key) (*tls.Config, error) {
	if key.Certificate == "" {
		return nil, fmt.Errorf("No certificates defined for key %s", key.Name)
	}
	certs, err := parseCertChain(key.Certificate)
	if err != nil {
		return nil, err
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("Key %s certificate file did not contain any certificates")
	}
	leaf, err := x509.ParseCertificate(certs[0])
	if err != nil {
		return nil, err
	}
	if !p11token.SameKey(key.Public(), leaf.PublicKey) {
		return nil, errors.New("Certificate does not match private key in token")
	}
	cert := tls.Certificate{
		Certificate: certs,
		PrivateKey:  key,
		Leaf:        leaf,
	}
	return &tls.Config{
		Certificates:             []tls.Certificate{cert},
		PreferServerCipherSuites: true,
		SessionTicketsDisabled:   true,
		MinVersion:               tls.VersionTLS12,
	}, nil
}

func Serve(conf *config.Config, keyMap map[string]*p11token.Key) error {
	handler := &Handler{
		Config: conf,
		KeyMap: keyMap,
	}
	tconf, err := makeTlsConfig(conf, keyMap[conf.Server.Key])
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
