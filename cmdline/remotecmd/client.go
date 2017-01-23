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
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
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

func callRemote(endpoint, method string, query *url.Values, body io.ReadSeeker) (*http.Response, error) {
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
	request := &http.Request{
		Method: method,
		URL:    url,
		Header: http.Header{"User-Agent": []string{config.UserAgent}},
	}
	if body != nil {
		size, err := body.Seek(0, io.SeekEnd)
		if err != nil {
			return nil, fmt.Errorf("failed to seek input file: %s", err)
		}
		request.ContentLength = size
	}
	response, err := doRequest(tconf, request, body)
	if err != nil {
		return nil, err
	} else if response.StatusCode >= 300 {
		bodybytes, _ := ioutil.ReadAll(response.Body)
		return nil, fmt.Errorf("HTTP error for %s: %s\n%s", url, response.Status, bodybytes)
	}
	return response, nil
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

func doRequest(tconf *tls.Config, req *http.Request, bodyFile io.ReadSeeker) (response *http.Response, err error) {
	host, port, err := splitHostPort(req.URL)
	if err != nil {
		return nil, err
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: connectTimeout}
	transport := &http.Transport{TLSClientConfig: tconf}
	if err := http2.ConfigureTransport(transport); err != nil {
		return nil, err
	}
	client := &http.Client{Transport: transport}
	s := rand.New(rand.NewSource(time.Now().UnixNano()))
	order := s.Perm(len(ips))
	var ip net.IP
	for i, j := range order {
		ip = ips[j]
		ipaddr := fmt.Sprintf("[%s]:%s", ip.String(), port)
		dialContext := func(ctx context.Context, network, ignoreAddr string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, ipaddr)
		}
		transport.DialContext = dialContext
		if bodyFile != nil {
			if _, err := bodyFile.Seek(0, 0); err != nil {
				return nil, fmt.Errorf("unable to rewind request body file: %s", err)
			}
			req.Body = ioutil.NopCloser(bodyFile)
		}
		response, err = client.Do(req)
		if err2, ok := err.(temporary); ok && err2.Temporary() {
			fmt.Printf("%s\nunable to connect to %s; trying next server\n", err, ip)
			continue
		} else if err2 == nil {
			switch response.StatusCode {
			case http.StatusGatewayTimeout,
				http.StatusBadGateway,
				http.StatusServiceUnavailable,
				http.StatusInsufficientStorage:
				fmt.Printf("HTTP error for %s: %s\nunable to connect to %s; trying next server\n", req.URL, response.Status, ip)
				continue
			}
		}
		if i != 0 {
			fmt.Printf("successfully contacted %s\n", ip)
		}
		return
	}
	return
}

type temporary interface {
	Temporary() bool
}
