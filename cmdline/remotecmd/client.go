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

package remotecmd

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"

	"gerrit-pdt.unx.sas.com/tools/relic.git/cmdline/shared"
	"golang.org/x/net/http2"
)

func makeTlsConfig() (*tls.Config, error) {
	err := shared.InitConfig()
	if err != nil {
		return nil, err
	}
	config := shared.CurrentConfig
	if config.Remote == nil {
		return nil, errors.New("Missing remote section in config file")
	} else if config.Remote.Url == "" {
		return nil, errors.New("url is a required setting in 'remote' section of configuration")
	} else if config.Remote.CertFile == "" || config.Remote.KeyFile == "" || config.Remote.CaCert == "" {
		return nil, errors.New("certfile, keyfile, and cacert are required settings in 'remote' section of configuration")
	}
	tlscert, err := tls.LoadX509KeyPair(config.Remote.CertFile, config.Remote.KeyFile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	cacert, err := ioutil.ReadFile(config.Remote.CaCert)
	if err != nil {
		return nil, err
	}
	if !pool.AppendCertsFromPEM(cacert) {
		return nil, errors.New("Failed to parse CA certificates")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{tlscert},
		RootCAs:      pool,
	}, nil
}

func callRemote(endpoint, method string, query *url.Values, body interface{}) (*http.Response, error) {
	tconf, err := makeTlsConfig()
	if err != nil {
		return nil, err
	}
	url, err := url.Parse(shared.CurrentConfig.Remote.Url)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse remote URL: %s", err)
	}
	eurl, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}
	url = url.ResolveReference(eurl)
	if query != nil {
		url.RawQuery = query.Encode()
	}
	transport := &http.Transport{TLSClientConfig: tconf}
	if err := http2.ConfigureTransport(transport); err != nil {
		return nil, err
	}
	client := &http.Client{Transport: transport}
	request := &http.Request{
		Method: method,
		URL:    url,
	}
	if body != nil {
		if reader, ok := body.(io.Reader); ok {
			if file, ok := reader.(*os.File); ok {
				stat, err := file.Stat()
				if err != nil {
					return nil, err
				}
				request.ContentLength = stat.Size()
			} else if file, ok := reader.(*bytes.Reader); ok {
				request.ContentLength = int64(file.Len())
			}
			request.Body = ioutil.NopCloser(reader)
		} else {
			var bodybytes []byte
			if body, ok := body.([]byte); ok {
				bodybytes = body
			} else {
				bodybytes, err = json.Marshal(body)
				if err != nil {
					return nil, err
				}
			}
			request.ContentLength = int64(len(bodybytes))
			request.Body = ioutil.NopCloser(bytes.NewReader(bodybytes))
			request.Header.Set("Content-Type", "application/json")
		}
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode >= 300 {
		bodybytes, _ := ioutil.ReadAll(response.Body)
		return nil, fmt.Errorf("HTTP error for %s: %s\n%s", url, response.Status, bodybytes)
	}
	return response, nil
}
