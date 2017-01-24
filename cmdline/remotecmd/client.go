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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"gerrit-pdt.unx.sas.com/tools/relic.git/cmdline/shared"
	"gerrit-pdt.unx.sas.com/tools/relic.git/config"
	"golang.org/x/net/http2"
)

const connectTimeout = time.Second * 15

func makeTlsConfig() (*tls.Config, error) {
	err := shared.InitConfig()
	if err != nil {
		return nil, err
	}
	config := shared.CurrentConfig
	if config.Remote == nil {
		return nil, errors.New("Missing remote section in config file")
	} else if config.Remote.Url == "" && config.Remote.DirectoryUrl == "" {
		return nil, errors.New("url or DirectoryUrl must be set in 'remote' section of configuration")
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

func callRemote(endpoint, method string, query *url.Values, body io.ReadSeeker) (*http.Response, error) {
	if err := shared.InitConfig(); err != nil {
		return nil, err
	}
	bases := []string{shared.CurrentConfig.Remote.Url}
	if dirurl := shared.CurrentConfig.Remote.DirectoryUrl; dirurl != "" {
		newBases, err := getDirectory(dirurl)
		if err != nil {
			return nil, err
		} else if len(newBases) > 0 {
			fmt.Println("new bases:", newBases)
			bases = newBases
		}
	}
	return doRequest(bases, endpoint, method, query, body)
}

func getDirectory(dirurl string) ([]string, error) {
	response, err := doRequest([]string{dirurl}, "directory", "GET", nil, nil)
	if err != nil {
		return nil, err
	}
	bodybytes, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	text := strings.Trim(string(bodybytes), "\r\n")
	if len(text) > 0 {
		return strings.Split(text, "\r\n"), nil
	} else {
		return nil, nil
	}
}

func splitHostPort(u *url.URL) (host, port string, err error) {
	s := u.Host
	hasPort := strings.LastIndex(s, ":") > strings.LastIndex(s, "]")
	if !hasPort {
		switch u.Scheme {
		case "http":
			s += ":80"
		case "https":
			s += ":443"
		default:
			return "", "", fmt.Errorf("unsupported scheme: %s", u.Scheme)
		}
	}
	return net.SplitHostPort(s)
}

func buildRequest(base, endpoint, method string, query *url.Values, bodyFile io.ReadSeeker) (*http.Request, error) {
	eurl, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}
	url, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse remote URL: %s", err)
	}
	url = url.ResolveReference(eurl)
	if query != nil {
		url.RawQuery = query.Encode()
	}
	request := &http.Request{
		Method: method,
		URL:    url,
		Header: http.Header{"User-Agent": []string{config.UserAgent}},
	}
	if bodyFile != nil {
		size, err := bodyFile.Seek(0, io.SeekEnd)
		if err != nil {
			return nil, fmt.Errorf("failed to seek input file: %s", err)
		}
		request.ContentLength = size
		bodyFile.Seek(0, io.SeekStart)
		request.Body = ioutil.NopCloser(bodyFile)
	}
	return request, nil
}

func doRequest(bases []string, endpoint, method string, query *url.Values, bodyFile io.ReadSeeker) (response *http.Response, err error) {
	tconf, err := makeTlsConfig()
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: connectTimeout}
	transport := &http.Transport{TLSClientConfig: tconf, DialContext: dialer.DialContext}
	if err := http2.ConfigureTransport(transport); err != nil {
		return nil, err
	}
	client := &http.Client{Transport: transport}

	for i, base := range bases {
		var request *http.Request
		request, err = buildRequest(base, endpoint, method, query, bodyFile)
		if err != nil {
			return nil, err
		}
		response, err = client.Do(request)
		if err == nil && response.StatusCode >= 300 {
			body, _ := ioutil.ReadAll(response.Body)
			err = ResponseError{method, request.URL.String(), response.StatusCode, string(body)}
		}
		if err2, ok := err.(temporary); ok && err2.Temporary() {
			fmt.Printf("%s\nunable to connect to %s; trying next server\n", err, request.URL)
		} else {
			if err == nil && i != 0 {
				fmt.Printf("successfully contacted %s\n", request.URL)
			}
			return
		}
	}
	return
}

type temporary interface {
	Temporary() bool
}

type ResponseError struct {
	Method     string
	Url        string
	StatusCode int
	BodyText   string
}

func (e ResponseError) Error() string {
	return fmt.Sprintf("HTTP error: %s %s: %s\n%s", e.Method, e.Url, e.StatusCode, e.BodyText)
}

func (e ResponseError) Temporary() bool {
	switch e.StatusCode {
	case http.StatusGatewayTimeout,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusInsufficientStorage:
		return true
	default:
		return false
	}
}
