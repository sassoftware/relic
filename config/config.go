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

package config

import (
	"errors"
	"fmt"
	"io/ioutil"
	"strings"

	"gopkg.in/yaml.v2"
)

const defaultMaxDocSize = 10000000

var Version = "unknown" // set this at link time
var UserAgent = "relic/" + Version
var Author = "SAS Institute Inc."

type TokenConfig struct {
	Provider string  // Path to PKCS#11 provider module (required)
	Label    string  // Select a token by label
	Serial   string  // Select a token by serial number
	Pin      *string // PIN to use, otherwise will be prompted. Can be empty. (optional)
	Timeout  int     // (server) Terminate command after N seconds (default 300)
	User     *uint   // User argument for PKCS#11 login (optional)

	name string
}

type ToolConfig struct {
	Command string // Command template
	Timeout int    // (server) Terminate command after N seconds (default 300)
}

type KeyConfig struct {
	Token           string   // Token section to use for this key (linux)
	Tool            string   // Tool section to use for this key (windows)
	Alias           string   // This is an alias for another key
	Label           string   // Select a key by label
	Id              string   // Select a key by ID (hex notation)
	PgpCertificate  string   // Path to PGP certificate associated with this key
	X509Certificate string   // Path to X.509 certificate associated with this key
	Roles           []string // List of user roles that can use this key
	Timestamp       bool     // If true, attach a timestamped countersignature when possible
	Hide            bool     // If true, then omit this key from 'remote list-keys'

	Params map[string]string // Parameters for a tool-based key, substituted into the command-line

	name  string
	token *TokenConfig
	tool  *ToolConfig
}

type ServerConfig struct {
	Listen   string // Port to listen for TLS connections
	KeyFile  string // Path to TLS key file
	CertFile string // Path to TLS certificate chain
	LogFile  string // Optional error log

	MaxDocSize     int64 // Largest request that will be spooled to RAM
	MaxDiskUsage   uint  // Max disk usage in megabytes
	DebugDiskUsage bool

	// URLs to all servers in the cluster. If a client uses DirectoryUrl to
	// point to this server (or a load balancer), then we will give them these
	// URLs as a means to distribute load without needing a middle-box.
	Siblings []string
}

type ClientConfig struct {
	Nickname string   // Name that appears in audit log entries
	Roles    []string // List of roles that this client possesses
}

type RemoteConfig struct {
	Url          string // URL of remote server
	DirectoryUrl string // URL of directory server
	KeyFile      string // Path to TLS client key file
	CertFile     string // Path to TLS client certificate
	CaCert       string // Path to CA certificate
}

type TimestampConfig struct {
	Urls    []string // List of timestamp server URLs
	Timeout int      // Connect timeout in seconds
	CaCert  string   // Path to CA certificate
}

type Config struct {
	Tokens    map[string]*TokenConfig  `,omitempty`
	Tools     map[string]*ToolConfig   `,omitempty`
	Keys      map[string]*KeyConfig    `,omitempty`
	Server    *ServerConfig            `,omitempty`
	Clients   map[string]*ClientConfig `,omitempty`
	Remote    *RemoteConfig            `,omitempty`
	Timestamp *TimestampConfig         `,omitempty`

	PinFile string // Optional YAML file with additional token PINs

	path string
}

func ReadFile(path string) (*Config, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	config := new(Config)
	err = yaml.Unmarshal(data, config)
	if err != nil {
		return nil, err
	}
	normalized := make(map[string]*ClientConfig)
	for fingerprint, client := range config.Clients {
		if len(fingerprint) != 64 {
			return nil, errors.New("Client keys must be hex-encoded SHA256 digests of the public key")
		}
		lower := strings.ToLower(fingerprint)
		normalized[lower] = client
	}
	config.Clients = normalized
	if config.Server != nil && config.Server.MaxDocSize == 0 {
		config.Server.MaxDocSize = defaultMaxDocSize
	}
	if config.PinFile != "" {
		contents, err := ioutil.ReadFile(config.PinFile)
		if err != nil {
			return nil, fmt.Errorf("error reading PinFile: %s", err)
		}
		pinMap := make(map[string]string)
		if err := yaml.Unmarshal(contents, pinMap); err != nil {
			return nil, fmt.Errorf("error reading PinFile: %s", err)
		}
		for token, pin := range pinMap {
			tokenConf := config.Tokens[token]
			if tokenConf != nil {
				ppin := pin
				tokenConf.Pin = &ppin
			}
		}
	}
	for tokenName, tokenConf := range config.Tokens {
		tokenConf.name = tokenName
	}
	for keyName, keyConf := range config.Keys {
		keyConf.name = keyName
		if keyConf.Token != "" {
			keyConf.token = config.Tokens[keyConf.Token]
		}
		if keyConf.Tool != "" {
			keyConf.tool = config.Tools[keyConf.Tool]
		}
	}
	config.path = path
	return config, nil
}

func (config *Config) GetToken(tokenName string) (*TokenConfig, error) {
	if config.Tokens == nil {
		return nil, errors.New("No tokens defined in configuration")
	}
	tokenConf, ok := config.Tokens[tokenName]
	if !ok {
		return nil, fmt.Errorf("Token \"%s\" not found in configuration", tokenName)
	} else {
		return tokenConf, nil
	}
}

func (config *Config) GetKey(keyName string) (*KeyConfig, error) {
	keyConf, ok := config.Keys[keyName]
	if !ok {
		return nil, fmt.Errorf("Key \"%s\" not found in configuration", keyName)
	} else if keyConf.Alias != "" {
		keyConf, ok = config.Keys[keyConf.Alias]
		if !ok {
			return nil, fmt.Errorf("Alias \"%s\" points to undefined key \"%s\"", keyName, keyConf.Alias)
		}
	}
	if keyConf.Token == "" && keyConf.Tool == "" {
		return nil, fmt.Errorf("Key \"%s\" does not specify required value 'token' or 'tool'", keyName)
	} else {
		return keyConf, nil
	}
}

func (config *Config) NewKey(name string) *KeyConfig {
	if config.Keys == nil {
		config.Keys = make(map[string]*KeyConfig)
	}
	config.Keys[name] = &KeyConfig{name: name}
	return config.Keys[name]
}

func (config *Config) Path() string {
	return config.path
}

func (config *Config) GetTimestampConfig() (*TimestampConfig, error) {
	tconf := config.Timestamp
	if tconf == nil {
		return nil, errors.New("No timestamp section exists in the configuration")
	} else if len(tconf.Urls) == 0 {
		return nil, errors.New("No timestamp urls are defined in the configuration")
	} else {
		return tconf, nil
	}
}
