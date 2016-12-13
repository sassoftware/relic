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

	"gopkg.in/yaml.v2"
)

type TokenConfig struct {
	Provider string // Path to PKCS#11 provider module (required)
	Label    string // Select a token by label
	Serial   string // Select a token by serial number
	Pin      string // PIN to use, otherwise will be prompted (optional)
}

type KeyConfig struct {
	Token       string   // Token section to use for this key (required)
	Label       string   // Select a key by label
	Id          string   // Select a key by ID (hex notation)
	Certificate string   // Path to certificate associated with this key
	Roles       []string // List of user roles that can use this key
}

type ServerConfig struct {
	Listen string // Port to listen for TLS connections
	Key    string // Name of key section to use for serving TLS
}

type Config struct {
	Tokens map[string]*TokenConfig
	Keys   map[string]*KeyConfig
	Server *ServerConfig
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
	} else if keyConf.Token == "" {
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
		if len(keyConf.Roles) > 0 {
			keys = append(keys, keyName)
		}
	}
	return
}
