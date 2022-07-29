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

package p11token

import (
	"context"
	"errors"
	"fmt"
	"io"
	"runtime"
	"sync"

	"github.com/miekg/pkcs11"

	"github.com/sassoftware/relic/v7/config"
	"github.com/sassoftware/relic/v7/lib/passprompt"
	"github.com/sassoftware/relic/v7/signers/sigerrors"
	"github.com/sassoftware/relic/v7/token"
)

const (
	CKS_RO_PUBLIC_SESSION = 0
	CKS_RO_USER_FUNCTIONS = 1
	CKS_RW_PUBLIC_SESSION = 2
	CKS_RW_USER_FUNCTIONS = 3
	CKS_RW_SO_FUNCTIONS   = 4

	CKA_ID            = pkcs11.CKA_ID
	CKA_LABEL         = pkcs11.CKA_LABEL
	CKA_SERIAL_NUMBER = pkcs11.CKA_SERIAL_NUMBER

	CKK_RSA   = pkcs11.CKK_RSA
	CKK_ECDSA = pkcs11.CKK_ECDSA
)

func init() {
	token.Openers["pkcs11"] = open
	token.Listers["pkcs11"] = List
}

var providerMap map[string]*pkcs11.Ctx
var providerMutex sync.Mutex

type Token struct {
	config    *config.Config
	tokenConf *config.TokenConfig
	ctx       *pkcs11.Ctx
	sh        pkcs11.SessionHandle
	mutex     sync.Mutex
}

func List(provider string, output io.Writer) error {
	ctx := pkcs11.New(provider)
	if ctx == nil {
		return errors.New("Failed to initialize pkcs11 provider")
	}
	defer ctx.Destroy()
	if err := ctx.Initialize(); err != nil {
		return err
	}
	slots, err := ctx.GetSlotList(false)
	if err != nil {
		return err
	}
	for _, slot := range slots {
		info, err := ctx.GetTokenInfo(slot)
		if rv, ok := err.(pkcs11.Error); ok && rv == pkcs11.CKR_TOKEN_NOT_PRESENT {
			continue
		}
		fmt.Fprintf(output, "slot %d:\n manuf:  %s\n model:  %s\n label:  %s\n serial: %s\n", slot, info.ManufacturerID, info.Model, info.Label, info.SerialNumber)
	}
	return nil
}

// Load a PKCS#11 provider, open a session, and login
func Open(config *config.Config, tokenName string, pinProvider passprompt.PasswordGetter) (*Token, error) {
	tokenConf, err := config.GetToken(tokenName)
	if err != nil {
		return nil, err
	}
	ctx, err := openLib(tokenConf, true)
	if err != nil {
		return nil, err
	}
	tok := &Token{
		ctx:       ctx,
		config:    config,
		tokenConf: tokenConf,
	}
	runtime.SetFinalizer(tok, (*Token).Close)
	slot, err := tok.findSlot()
	if err != nil {
		tok.Close()
		return nil, err
	}
	mode := uint(pkcs11.CKF_SERIAL_SESSION | pkcs11.CKF_RW_SESSION)
	sh, err := tok.ctx.OpenSession(slot, mode)
	if err != nil {
		tok.Close()
		return nil, err
	}
	tok.sh = sh
	err = tok.autoLogIn(pinProvider)
	if err != nil {
		tok.Close()
		return nil, err
	}
	return tok, nil
}

// compat shim for token.Openers
func open(cfg *config.Config, tokenName string, prompt passprompt.PasswordGetter) (token.Token, error) {
	return Open(cfg, tokenName, prompt)
}

func openLib(tokenConf *config.TokenConfig, write bool) (*pkcs11.Ctx, error) {
	if tokenConf.Provider == "" {
		return nil, errors.New("Missing attribute \"provider\" in token configuration")
	}
	providerMutex.Lock()
	defer providerMutex.Unlock()
	if providerMap == nil {
		providerMap = make(map[string]*pkcs11.Ctx)
	}
	ctx, ok := providerMap[tokenConf.Provider]
	if ok {
		return ctx, nil
	}
	ctx = pkcs11.New(tokenConf.Provider)
	if ctx == nil {
		return nil, errors.New("Failed to initialize pkcs11 provider")
	}
	err := ctx.Initialize()
	if err != nil {
		ctx.Destroy()
		return nil, err
	}
	providerMap[tokenConf.Provider] = ctx
	return ctx, nil
}

// Close the token session
func (tok *Token) Close() error {
	tok.mutex.Lock()
	defer tok.mutex.Unlock()
	var err error
	if tok.ctx != nil {
		err = tok.ctx.CloseSession(tok.sh)
		tok.ctx = nil
		runtime.SetFinalizer(tok, nil)
	}
	return err
}

func (tok *Token) Config() *config.TokenConfig {
	return tok.tokenConf
}

func (tok *Token) findSlot() (uint, error) {
	tokenConf := tok.tokenConf
	slots, err := tok.ctx.GetSlotList(false)
	if err != nil {
		return 0, nil
	}
	candidates := make([]uint, 0, len(slots))
	for _, slot := range slots {
		info, err := tok.ctx.GetTokenInfo(slot)
		if err != nil {
			if rv, ok := err.(pkcs11.Error); ok && rv == pkcs11.CKR_TOKEN_NOT_PRESENT {
				continue
			}
			return 0, err
		}
		if tokenConf.Label != "" && tokenConf.Label != info.Label {
			continue
		} else if tokenConf.Serial != "" && tokenConf.Serial != info.SerialNumber {
			continue
		}
		candidates = append(candidates, slot)
	}
	if len(candidates) == 0 {
		return 0, errors.New("No token found with the specified attributes")
	} else if len(candidates) != 1 {
		return 0, errors.New("Multiple tokens matched the specified attributes")
	} else {
		return candidates[0], nil
	}
}

// Test that the token is responding and the user is (still) logged in
func (tok *Token) isLoggedIn() (bool, error) {
	tok.mutex.Lock()
	defer tok.mutex.Unlock()
	info, err := tok.ctx.GetSessionInfo(tok.sh)
	if err != nil {
		return false, err
	}
	return (info.State == CKS_RO_USER_FUNCTIONS || info.State == CKS_RW_USER_FUNCTIONS || info.State == CKS_RW_SO_FUNCTIONS), nil
}

func (tok *Token) Ping(ctx context.Context) error {
	loggedIn, err := tok.isLoggedIn()
	if err != nil {
		return err
	} else if !loggedIn {
		return errors.New("token not logged in")
	}
	return nil
}

func (tok *Token) login(user uint, pin string) error {
	tok.mutex.Lock()
	defer tok.mutex.Unlock()
	err := tok.ctx.Login(tok.sh, user, pin)
	if err != nil {
		if rv, ok := err.(pkcs11.Error); ok && rv == pkcs11.CKR_PIN_INCORRECT {
			return sigerrors.PinIncorrectError{}
		}
	}
	return err
}

func (tok *Token) autoLogIn(pinProvider passprompt.PasswordGetter) error {
	tokenConf := tok.tokenConf
	loggedIn, err := tok.isLoggedIn()
	if err != nil {
		return err
	}
	if loggedIn {
		return nil
	}
	var user uint = pkcs11.CKU_USER
	if tokenConf.User != nil {
		user = *tokenConf.User
	}
	loginFunc := func(pin string) (bool, error) {
		if err := tok.login(user, pin); err == nil {
			return true, nil
		} else if _, ok := err.(sigerrors.PinIncorrectError); ok {
			return false, nil
		} else {
			return false, err
		}
	}
	initialPrompt := fmt.Sprintf("PIN for token %s user %08x: ", tokenConf.Name(), user)
	keyringUser := fmt.Sprintf("%s.%08x", tokenConf.Name(), user)
	return token.Login(tokenConf, pinProvider, loginFunc, keyringUser, initialPrompt)
}

func (tok *Token) getAttribute(handle pkcs11.ObjectHandle, attr uint) []byte {
	attrs, err := tok.ctx.GetAttributeValue(tok.sh, handle, []*pkcs11.Attribute{pkcs11.NewAttribute(attr, nil)})
	if err != nil {
		return nil
	}
	return attrs[0].Value
}

func (tok *Token) findObject(attrs []*pkcs11.Attribute) ([]pkcs11.ObjectHandle, error) {
	if err := tok.ctx.FindObjectsInit(tok.sh, attrs); err != nil {
		return nil, err
	}
	objects, _, err := tok.ctx.FindObjects(tok.sh, 10)
	if err != nil {
		_ = tok.ctx.FindObjectsFinal(tok.sh)
		return nil, err
	}
	if err := tok.ctx.FindObjectsFinal(tok.sh); err != nil {
		return nil, err
	}
	return objects, nil
}
