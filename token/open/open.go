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
	"fmt"

	"github.com/sassoftware/relic/config"
	"github.com/sassoftware/relic/lib/passprompt"
	"github.com/sassoftware/relic/token"
	"github.com/sassoftware/relic/token/filetoken"
	"github.com/sassoftware/relic/token/p11token"
	"github.com/sassoftware/relic/token/scdtoken"
)

func Token(cfg *config.Config, tokenName string, prompt passprompt.PasswordGetter) (token.Token, error) {
	tcfg, err := cfg.GetToken(tokenName)
	if err != nil {
		return nil, err
	}
	switch tcfg.Type {
	case "pkcs11":
		return p11token.Open(cfg, tokenName, prompt)
	case "file":
		return filetoken.Open(cfg, tokenName, prompt)
	case "scdaemon":
		return scdtoken.Open(cfg, tokenName, prompt)
	default:
		return nil, fmt.Errorf("unknown token type %s", tcfg.Type)
	}
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
	key, err := token.GetKey(keyName)
	if err != nil {
		token.Close()
		return nil, err
	}
	return key, nil
}
