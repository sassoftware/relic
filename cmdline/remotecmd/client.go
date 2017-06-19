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

package remotecmd

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/sassoftware/relic/cmdline/shared"
	"github.com/sassoftware/relic/config"
	"github.com/sassoftware/relic/lib/compresshttp"
	"github.com/sassoftware/relic/lib/x509tools"
	"golang.org/x/net/http2"
)

const connectTimeout = time.Second * 15

type ReaderGetter interface {
	GetReader() (io.Reader, error)
}

// Make a single API request to a named endpoint, handling directory lookup and failover automatically.
func CallRemote(endpoint, method string, query *url.Values, body ReaderGetter) (*http.Response, error) {
	if err := shared.InitConfig(); err != nil {
		return nil, err
	}
	if shared.CurrentConfig.Remote == nil {
		return nil, errors.New("config file has no \"remote\" section")
	}
	encodings := compresshttp.AcceptedEncodings
	bases := []string{shared.CurrentConfig.Remote.URL}
	if dirurl := shared.CurrentConfig.Remote.DirectoryURL; dirurl != "" {
		newBases, serverEncodings, err := getDirectory(dirurl)
		if err != nil {
			return nil, err
		} else if len(newBases) > 0 {
			bases = newBases
		}
		encodings = serverEncodings
	}
	return doRequest(bases, endpoint, method, encodings, query, body)
}

// Call the configured directory URL to get a list of servers to try.
// callRemote() calls this automatically, use that instead.
func getDirectory(dirurl string) ([]string, string, error) {
	response, err := doRequest([]string{dirurl}, "directory", "GET", "", nil, nil)
	if err != nil {
		return nil, "", err
	}
	encodings := response.Header.Get("Accept-Encoding")
	bodybytes, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, "", err
	}
	response.Body.Close()
	text := strings.Trim(string(bodybytes), "\r\n")
	if len(text) == 0 {
		return nil, encodings, nil
	}
	return strings.Split(text, "\r\n"), encodings, nil
}

// Build a HTTP request from various bits and pieces
func buildRequest(base, endpoint, method, encoding string, query *url.Values, bodyFile ReaderGetter) (*http.Request, error) {
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
	if encoding != "" {
		request.Header.Set("Accept-Encoding", encoding)
	}
	if bodyFile != nil {
		stream, err := bodyFile.GetReader()
		if err != nil {
			return nil, err
		}
		request.Body = ioutil.NopCloser(stream)
		if err := compresshttp.CompressRequest(request, encoding); err != nil {
			return nil, err
		}
	}
	return request, nil
}

// Build TLS config based on client configuration
func makeTLSConfig() (*tls.Config, error) {
	err := shared.InitConfig()
	if err != nil {
		return nil, err
	}
	config := shared.CurrentConfig
	if config.Remote == nil {
		return nil, errors.New("Missing remote section in config file")
	} else if config.Remote.URL == "" && config.Remote.DirectoryURL == "" {
		return nil, errors.New("url or directoryUrl must be set in 'remote' section of configuration")
	} else if config.Remote.CertFile == "" || config.Remote.KeyFile == "" {
		return nil, errors.New("certfile and keyfile are required settings in 'remote' section of configuration")
	}
	tlscert, err := tls.LoadX509KeyPair(config.Remote.CertFile, config.Remote.KeyFile)
	if err != nil {
		return nil, err
	}
	tconf := &tls.Config{Certificates: []tls.Certificate{tlscert}}
	x509tools.SetKeyLogFile(tconf)
	if err := x509tools.LoadCertPool(config.Remote.CaCert, tconf); err != nil {
		return nil, err
	}
	return tconf, nil
}

// Transact one request, trying multiple servers if necessary. Internal use only.
func doRequest(bases []string, endpoint, method, encodings string, query *url.Values, bodyFile ReaderGetter) (response *http.Response, err error) {
	tconf, err := makeTLSConfig()
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: connectTimeout}
	transport := &http.Transport{TLSClientConfig: tconf, DialContext: dialer.DialContext}
	if err := http2.ConfigureTransport(transport); err != nil {
		return nil, err
	}
	client := &http.Client{Transport: transport}

loop:
	for i, base := range bases {
		var request *http.Request
		request, err = buildRequest(base, endpoint, method, encodings, query, bodyFile)
		if err != nil {
			return nil, err
		}
		response, err = client.Do(request)
		if request.Body != nil {
			request.Body.Close()
		}
		if err == nil {
			if response.StatusCode < 300 {
				if i != 0 {
					fmt.Printf("successfully contacted %s\n", request.URL)
				}
				break loop
			}
			// HTTP error, probably a 503
			body, _ := ioutil.ReadAll(response.Body)
			response.Body.Close()
			err = ResponseError{method, request.URL.String(), response.Status, response.StatusCode, string(body)}
		}
		if response != nil && response.StatusCode == http.StatusNotAcceptable && encodings != "" {
			// try again without compression
			encodings = ""
			goto loop
		} else if isTemporary(err) && i+1 < len(bases) {
			fmt.Printf("%s\nunable to connect to %s; trying next server\n", err, request.URL)
		} else {
			return nil, err
		}
	}
	if response != nil {
		if err := compresshttp.DecompressResponse(response); err != nil {
			return nil, err
		}
	}
	return
}

func setDigestQueryParam(query url.Values) error {
	if shared.ArgDigest == "" {
		return nil
	}
	if _, err := shared.GetDigest(); err != nil {
		return err
	}
	query.Add("digest", shared.ArgDigest)
	return nil
}

// Check if an error is something recoverable, i.e. if we should continue to
// try another server. In practice, anything other than a HTTP 4XX status will
// result in a retry.
func isTemporary(err error) bool {
	if e, ok := err.(temporary); ok && e.Temporary() {
		return true
	}
	// unpack error wrappers
	if e, ok := err.(*url.Error); ok {
		err = e.Err
	}
	if e, ok := err.(*net.OpError); ok {
		err = e.Err
	}
	// treat any syscall error as something recoverable
	if _, ok := err.(*os.SyscallError); ok {
		return true
	}
	return false
}

type temporary interface {
	Temporary() bool
}

type ResponseError struct {
	Method     string
	URL        string
	Status     string
	StatusCode int
	BodyText   string
}

func (e ResponseError) Error() string {
	return fmt.Sprintf("HTTP error:\n%s %s\n%s\n%s", e.Method, e.URL, e.Status, e.BodyText)
}

func (e ResponseError) Temporary() bool {
	switch e.StatusCode {
	case http.StatusGatewayTimeout,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusInsufficientStorage,
		http.StatusInternalServerError:
		return true
	default:
		return false
	}
}
