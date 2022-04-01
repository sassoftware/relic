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

package token

import (
	"errors"
	"fmt"
	"io"

	"github.com/sassoftware/relic/v7/config"
	"github.com/sassoftware/relic/v7/lib/passprompt"
	"github.com/sassoftware/relic/v7/signers/sigerrors"
)

func Login(tokenConf *config.TokenConfig, pinProvider passprompt.PasswordGetter, loginFunc passprompt.LoginFunc, keyringUser, initialPrompt string) error {
	if tokenConf.Pin != nil {
		ok, err := loginFunc(*tokenConf.Pin)
		if err != nil {
			return err
		} else if !ok {
			return sigerrors.PinIncorrectError{}
		} else {
			return nil
		}
	}
	if initialPrompt == "" {
		initialPrompt = fmt.Sprintf("PIN for token %s: ", tokenConf.Name())
	}
	failPrefix := "Incorrect PIN\r\n"
	var keyringService string
	if tokenConf.UseKeyring {
		keyringService = "relic"
	}
	err := passprompt.Login(loginFunc, pinProvider, keyringService, keyringUser, initialPrompt, failPrefix)
	if err == io.EOF {
		if pinProvider == nil {
			msg := "PIN required but none was provided"
			if tokenConf.UseKeyring {
				msg += "; use 'relic ping' to save password in keyring"
			}
			return errors.New(msg)
		}
		return errors.New("Aborted")
	}
	return err
}
