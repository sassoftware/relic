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

package open

import (
	"context"
	"fmt"
	"io"

	"github.com/sassoftware/relic/v7/config"
	"github.com/sassoftware/relic/v7/lib/passprompt"
	"github.com/sassoftware/relic/v7/token"

	// Token types that don't require cgo
	_ "github.com/sassoftware/relic/v7/token/awstoken"
	_ "github.com/sassoftware/relic/v7/token/azuretoken"
	_ "github.com/sassoftware/relic/v7/token/filetoken"
	_ "github.com/sassoftware/relic/v7/token/gcloudtoken"
	_ "github.com/sassoftware/relic/v7/token/scdtoken"
)

func Token(cfg *config.Config, tokenName string, prompt passprompt.PasswordGetter) (token.Token, error) {
	tcfg, err := cfg.GetToken(tokenName)
	if err != nil {
		return nil, err
	}
	if ofunc := token.Openers[tcfg.Type]; ofunc != nil {
		return ofunc(cfg, tokenName, prompt)
	}
	var msg string
	if tcfg.Type == "pkcs11" {
		msg = " -- built without pkcs11 support"
	}
	return nil, fmt.Errorf("unknown token type %s%s", tcfg.Type, msg)
}

func Key(cfg *config.Config, keyName string, prompt passprompt.PasswordGetter) (token.Key, error) {
	keyConf, err := cfg.GetKey(keyName)
	if err != nil {
		return nil, err
	}
	token, err := Token(cfg, keyConf.Token, prompt)
	if err != nil {
		return nil, err
	}
	key, err := token.GetKey(context.Background(), keyName)
	if err != nil {
		token.Close()
		return nil, err
	}
	return key, nil
}

func List(tokenType, provider string, w io.Writer) error {
	if listFunc := token.Listers[tokenType]; listFunc != nil {
		return listFunc(provider, w)
	}
	if token.Openers[tokenType] != nil {
		return fmt.Errorf("list operation not supported for token type %s", tokenType)
	}
	var msg string
	if tokenType == "pkcs11" {
		msg = " -- built without pkcs11 support"
	}
	return fmt.Errorf("unknown token type %s%s", tokenType, msg)
}
