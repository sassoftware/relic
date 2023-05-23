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

package certloader

import (
	"crypto/x509"
	"errors"

	"software.sslmate.com/src/go-pkcs12"

	"github.com/sassoftware/relic/v7/lib/passprompt"
)

func ParsePKCS12(blob []byte, prompt passprompt.PasswordGetter) (*Certificate, error) {
	var password string
	var triedEmpty bool
	for {
		var err error
		password, err = prompt.GetPasswd("Password for PKCS12: ")
		if err != nil {
			return nil, err
		} else if password == "" {
			if triedEmpty {
				return nil, errors.New("aborted")
			}
			triedEmpty = true
		}
		priv, leaf, chain, err := pkcs12.DecodeChain(blob, password)
		if errors.Is(err, pkcs12.ErrIncorrectPassword) {
			continue
		} else if err != nil {
			return nil, err
		}
		certs := append([]*x509.Certificate{leaf}, chain...)
		return &Certificate{
			PrivateKey:   priv,
			Leaf:         leaf,
			Certificates: certs,
		}, nil
	}
}
