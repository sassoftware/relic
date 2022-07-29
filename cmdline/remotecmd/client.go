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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/oauth2"

	"github.com/sassoftware/relic/v7/cmdline/shared"
	"github.com/sassoftware/relic/v7/config"
	"github.com/sassoftware/relic/v7/internal/authmodel"
	"github.com/sassoftware/relic/v7/internal/httperror"
	"github.com/sassoftware/relic/v7/lib/compresshttp"
	"github.com/sassoftware/relic/v7/lib/x509tools"
)

type ReaderGetter interface {
	GetReader() (io.Reader, error)
}

type client struct {
	config      *config.RemoteConfig
	cli         *http.Client
	tokenSource oauth2.TokenSource
}

func newClient() (*client, error) {
	err := shared.InitClientConfig()
	if err != nil {
		return nil, err
	}
	cfg := shared.CurrentConfig.Remote
	if cfg == nil {
		return nil, errors.New("missing remote section in config file")
	} else if cfg.DirectoryURL == "" {
		if cfg.URL == "" {
			return nil, errors.New("url or directoryUrl must be set in 'remote' section of configuration")
		}
		cfg.DirectoryURL = cfg.URL
	}
	tconf, err := makeTLSConfig(cfg)
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{
		Timeout: time.Duration(cfg.ConnectTimeout) * time.Second,
	}
	transport := &http.Transport{TLSClientConfig: tconf, DialContext: dialer.DialContext}
	if err := http2.ConfigureTransport(transport); err != nil {
		return nil, err
	}
	client := &client{
		config: cfg,
		cli:    &http.Client{Transport: transport},
	}
	if cfg.AccessToken != "" {
		// static access token from environment
		client.tokenSource = oauth2.StaticTokenSource(&oauth2.Token{AccessToken: cfg.AccessToken})
	}
	if client.tokenSource == nil && tconf.GetClientCertificate == nil && !cfg.Interactive {
		return nil, errors.New("remote.certfile and remote.keyfile must be set")
	}
	// in case of interactive auth, wait until we have metadata
	return client, nil
}

// Make a single API request to a named endpoint, handling directory lookup and failover automatically.
func CallRemote(endpoint, method string, query *url.Values, body ReaderGetter) (*http.Response, error) {
	cli, err := newClient()
	if err != nil {
		return nil, err
	}
	cfg := shared.CurrentConfig.Remote
	bases := []string{cfg.DirectoryURL}
	metadata, serverEncodings, err := cli.getDirectory(cfg.DirectoryURL)
	if err != nil {
		return nil, err
	} else if len(metadata.Hosts) > 0 {
		// list of direct URLs provided
		bases = metadata.Hosts
	}
	if err := cli.interactiveAuth(metadata); err != nil {
		return nil, fmt.Errorf("configuring interactive authentication: %w", err)
	}
	return cli.doRequest(bases, endpoint, method, serverEncodings, query, body)
}

func (cli *client) interactiveAuth(metadata *authmodel.Metadata) error {
	if !cli.config.Interactive || cli.tokenSource != nil {
		// not needed
		return nil
	}
	for _, auth := range metadata.Auth {
		if auth.Type != authmodel.AuthTypeAzureAD {
			continue
		}
		var err error
		cli.tokenSource, err = azureTokenSource(auth.Authority, auth.ClientID, auth.Scopes)
		if err != nil {
			return err
		}
		break
	}
	return nil
}

// Call the configured directory URL to get a list of servers to try.
// callRemote() calls this automatically, use that instead.
func (cli *client) getDirectory(dirurl string) (*authmodel.Metadata, string, error) {
	response, err := cli.doRequest([]string{dirurl}, "directory", "GET", "", nil, nil)
	if err != nil {
		return nil, "", err
	}
	encodings := response.Header.Get("Accept-Encoding")
	bodybytes, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, "", err
	}
	response.Body.Close()
	m := new(authmodel.Metadata)
	if strings.Contains(response.Header.Get("Content-Type"), "json") {
		if err := json.Unmarshal(bodybytes, m); err != nil {
			return nil, "", err
		}
	} else {
		// legacy path
		text := strings.Trim(string(bodybytes), "\r\n")
		if len(text) == 0 {
			return nil, encodings, nil
		}
		m.Hosts = strings.Split(text, "\r\n")
	}
	return m, encodings, nil
}

// Build a HTTP request from various bits and pieces
func (cli *client) buildRequest(base, endpoint, method, encoding string, query *url.Values, bodyFile ReaderGetter) (*http.Request, error) {
	request, err := http.NewRequest(method, base, nil)
	if err != nil {
		return nil, err
	}
	request.URL, err = request.URL.Parse(endpoint)
	if err != nil {
		return nil, err
	}
	if query != nil {
		request.URL.RawQuery = query.Encode()
	}
	request.Header.Set("User-Agent", config.UserAgent)
	if encoding != "" {
		request.Header.Set("Accept-Encoding", encoding)
	}
	if cli.tokenSource != nil {
		tok, err := cli.tokenSource.Token()
		if err != nil {
			return nil, err
		}
		tok.SetAuthHeader(request)
	}
	if bodyFile != nil {
		stream, err := bodyFile.GetReader()
		if err != nil {
			return nil, err
		}
		request.Body = io.NopCloser(stream)
		if err := compresshttp.CompressRequest(request, encoding); err != nil {
			return nil, err
		}
	}
	if endpoint == "directory" {
		request.Header.Set("Accept", "application/json, */*")
	}
	return request, nil
}

// Build TLS config based on client configuration
func makeTLSConfig(cfg *config.RemoteConfig) (*tls.Config, error) {
	tconf := new(tls.Config)
	if err := x509tools.LoadCertPool(cfg.CaCert, tconf); err != nil {
		return nil, err
	}
	x509tools.SetKeyLogFile(tconf)
	if cfg.CertFile == "" && cfg.KeyFile == "" {
		return tconf, nil
	}
	var err error
	var certBytes, keyBytes []byte
	if strings.Contains(cfg.CertFile, "-----BEGIN") {
		certBytes = []byte(cfg.CertFile)
	} else {
		certBytes, err = os.ReadFile(cfg.CertFile)
		if err != nil {
			return nil, fmt.Errorf("remote.certfile: %w", err)
		}
	}
	if strings.Contains(cfg.KeyFile, "-----BEGIN") {
		keyBytes = []byte(cfg.KeyFile)
	} else {
		keyBytes, err = os.ReadFile(cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("remote.keyfile: %w", err)
		}
	}
	tlscert, err := tls.X509KeyPair(certBytes, keyBytes)
	if err != nil {
		return nil, err
	}
	// When the server is running behind nginx, nginx must be configured to send
	// at least one CA-cert to the client to pick from. However, it's not
	// feasible to list every cert the server would accept as most of them are
	// self-signed, so only a dummy cert is sent. Go is clever though, and if we
	// set tconf.Certificates here it will try to match it again what the server
	// claims to want, and if none match then no cert is sent at all. Work
	// around this by using GetClientCertificate so that the matching behavior
	// is bypassed and it always sends the configured client cert.
	tconf.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		return &tlscert, nil
	}
	return tconf, nil
}

// Transact one request, trying multiple servers if necessary. Internal use only.
func (cli *client) doRequest(bases []string, endpoint, method, encodings string, query *url.Values, bodyFile ReaderGetter) (response *http.Response, err error) {
	minAttempts := shared.CurrentConfig.Remote.Retries
	if len(bases) < minAttempts {
		var repeated []string
		for len(repeated) < minAttempts {
			repeated = append(repeated, bases...)
		}
		bases = repeated
	}

loop:
	for i, base := range bases {
		var request *http.Request
		request, err = cli.buildRequest(base, endpoint, method, encodings, query, bodyFile)
		if err != nil {
			return nil, err
		}
		response, err = cli.cli.Do(request)
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
			err = httperror.FromResponse(response)
		}
		if response != nil && response.StatusCode == http.StatusNotAcceptable && encodings != "" {
			// try again without compression
			encodings = ""
			goto loop
		} else if httperror.Temporary(err) && i+1 < len(bases) {
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
