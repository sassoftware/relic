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

	"github.com/mattn/go-shellwords"
	"gopkg.in/yaml.v2"
)

type TokenConfig struct {
	Provider string // Path to PKCS#11 provider module (required)
	Label    string // Select a token by label
	Serial   string // Select a token by serial number
	Pin      string // PIN to use, otherwise will be prompted (optional)
}

type ToolConfig struct {
	Command string // Command template
}

type KeyConfig struct {
	Token       string   // Token section to use for this key (linux)
	Tool        string   // Tool section to use for this key (windows)
	Label       string   // Select a key by label
	Id          string   // Select a key by ID (hex notation)
	Certificate string   // Path to certificate associated with this key
	Key         string   // Name of key container (windows)
	Roles       []string // List of user roles that can use this key
}

type ServerConfig struct {
	Listen   string // Port to listen for TLS connections
	KeyFile  string // Path to TLS key file
	CertFile string // Path to TLS certificate chain
}

type ClientConfig struct {
	Nickname string   // Name that appears in audit log entries
	Roles    []string // List of roles that this client possesses
}

type RemoteConfig struct {
	Url      string // URL of remote server
	KeyFile  string // Path to TLS client key file
	CertFile string // Path to TLS client certificate
	CaCert   string // Path to CA certificate
}

type Config struct {
	Tokens  map[string]*TokenConfig  `,omitempty`
	Tools   map[string]*ToolConfig   `,omitempty`
	Keys    map[string]*KeyConfig    `,omitempty`
	Server  *ServerConfig            `,omitempty`
	Clients map[string]*ClientConfig `,omitempty`
	Remote  *RemoteConfig            `,omitempty`

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
	if config.Keys == nil {
		return nil, errors.New("No keys defined in configuration")
	}
	keyConf, ok := config.Keys[keyName]
	if !ok {
		return nil, fmt.Errorf("Key \"%s\" not found in configuration", keyName)
	} else if keyConf.Token == "" && keyConf.Tool == "" {
		return nil, fmt.Errorf("Key \"%s\" does not specify required value 'token'", keyName)
	} else {
		return keyConf, nil
	}
}

func (config *Config) GetServedKeys() (keys []string) {
	if config.Keys == nil {
		return
	}
	for keyName, keyConf := range config.Keys {
		if len(keyConf.Roles) > 0 && keyConf.Tool == "" {
			keys = append(keys, keyName)
		}
	}
	return
}

func (config *Config) GetToolCmd(keyName, path string) ([]string, error) {
	if config.Keys == nil {
		return nil, errors.New("No keys defined in configuration")
	} else if config.Tools == nil {
		return nil, errors.New("No tools defined in configuration")
	}
	keyConf, ok := config.Keys[keyName]
	if !ok {
		return nil, fmt.Errorf("Key \"%s\" not found in configuration", keyName)
	} else if keyConf.Tool == "" {
		return nil, fmt.Errorf("Key \"%s\" does not specify required value 'tool'", keyName)
	}
	toolConf, ok := config.Tools[keyConf.Tool]
	if !ok {
		return nil, fmt.Errorf("Tool \"%s\" not found in configuration", keyConf.Tool)
	} else if toolConf.Command == "" {
		return nil, fmt.Errorf("Tool \"%s\" does not specify required value 'command'", keyConf.Tool)
	}
	words, err := shellwords.Parse(toolConf.Command)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse tool commandline: %s", err)
	}
	for i, word := range words {
		word = strings.Replace(word, "{file}", path, -1)
		word = strings.Replace(word, "{certificate}", keyConf.Certificate, -1)
		word = strings.Replace(word, "{key}", keyConf.Key, -1)
		words[i] = word
	}
	return words, nil
}

func (config *Config) Path() string {
	return config.path
}
