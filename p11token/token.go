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

package p11token

import (
	"errors"
	"runtime"
	"sync"

	"gerrit-pdt.unx.sas.com/tools/relic.git/config"
	"github.com/miekg/pkcs11"
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

type Token struct {
	config *config.Config
	name   string
	ctx    *pkcs11.Ctx
	sh     pkcs11.SessionHandle
	mutex  sync.Mutex
}

type PinProvider interface {
	WriteString(string)
	GetPin(tokenName string) (pin string, err error)
}

func Open(config *config.Config, tokenName string, pinProvider PinProvider) (*Token, error) {
	tokenConf, err := config.GetToken(tokenName)
	if err != nil {
		return nil, err
	}
	token, err := openLib(tokenConf, true)
	if err != nil {
		return nil, err
	}
	token.config = config
	token.name = tokenName
	slot, err := token.findSlot(tokenConf)
	if err != nil {
		token.Close()
		return nil, err
	}
	mode := uint(pkcs11.CKF_SERIAL_SESSION | pkcs11.CKF_RW_SESSION)
	sh, err := token.ctx.OpenSession(slot, mode)
	if err != nil {
		token.Close()
		return nil, err
	}
	token.sh = sh
	err = token.autoLogIn(false, tokenConf.Pin, pinProvider)
	if err != nil {
		token.Close()
		return nil, err
	}
	return token, nil
}

func openLib(tokenConf *config.TokenConfig, write bool) (*Token, error) {
	if tokenConf.Provider == "" {
		return nil, errors.New("Missing attribute \"provider\" in token configuration")
	}
	ctx := pkcs11.New(tokenConf.Provider)
	if ctx == nil {
		return nil, errors.New("Failed to initialize pkcs11 provider")
	}
	err := ctx.Initialize()
	if err != nil {
		ctx.Destroy()
		return nil, err
	}
	token := new(Token)
	token.ctx = ctx
	runtime.SetFinalizer(token, (*Token).Close)
	return token, nil
}

func (token *Token) Close() {
	token.mutex.Lock()
	defer token.mutex.Unlock()
	if token.ctx != nil {
		token.ctx.Finalize()
		token.ctx.Destroy()
		token.ctx = nil
		runtime.SetFinalizer(token, nil)
	}
}

func (token *Token) findSlot(tokenConf *config.TokenConfig) (uint, error) {
	slots, err := token.ctx.GetSlotList(false)
	if err != nil {
		return 0, nil
	}
	candidates := make([]uint, 0, len(slots))
	for _, slot := range slots {
		info, err := token.ctx.GetTokenInfo(slot)
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

func (token *Token) IsLoggedIn() (bool, error) {
	token.mutex.Lock()
	defer token.mutex.Unlock()
	info, err := token.ctx.GetSessionInfo(token.sh)
	if err != nil {
		return false, err
	}
	return (info.State == CKS_RO_USER_FUNCTIONS || info.State == CKS_RW_USER_FUNCTIONS || info.State == CKS_RW_SO_FUNCTIONS), nil
}

func (token *Token) Login(admin bool, pin string) error {
	token.mutex.Lock()
	defer token.mutex.Unlock()
	var userType uint
	if admin {
		userType = pkcs11.CKU_SO
	} else {
		userType = pkcs11.CKU_USER
	}
	err := token.ctx.Login(token.sh, userType, pin)
	if err != nil {
		if rv, ok := err.(pkcs11.Error); ok && rv == pkcs11.CKR_PIN_INCORRECT {
			return PinIncorrectError{}
		}
	}
	return err
}

func (token *Token) autoLogIn(admin bool, pin string, pinProvider PinProvider) error {
	loggedIn, err := token.IsLoggedIn()
	if err != nil {
		return err
	}
	if loggedIn {
		return nil
	}
	if pin != "" {
		err = token.Login(admin, pin)
		if err != nil {
			return err
		}
	} else if pinProvider != nil {
		for {
			pin, err = pinProvider.GetPin(token.name)
			if err != nil {
				return err
			} else if pin == "" {
				return errors.New("Aborted")
			}
			err = token.Login(admin, pin)
			if _, ok := err.(PinIncorrectError); ok {
				pinProvider.WriteString("Incorrect PIN")
				continue
			} else if err != nil {
				return err
			}
			break
		}
	} else {
		return errors.New("PIN required but none was provided")
	}
	return nil
}

func (token *Token) getAttribute(handle pkcs11.ObjectHandle, attr uint) []byte {
	attrs, err := token.ctx.GetAttributeValue(token.sh, handle, []*pkcs11.Attribute{pkcs11.NewAttribute(attr, nil)})
	if err != nil {
		return nil
	}
	return attrs[0].Value
}

func attrToInt(value []byte) uint {
	var n uint = 0
	for i := len(value) - 1; i >= 0; i-- {
		n = n<<8 | uint(value[i])
	}
	return n
}
