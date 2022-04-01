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

package assuan

// Implement a libassuan client and wrap useful functions in scdaemon

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/sassoftware/relic/v7/lib/dlog"
	"github.com/sassoftware/relic/v7/lib/x509tools"
	"github.com/sassoftware/relic/v7/signers/sigerrors"
)

type ScdConn struct {
	*Conn
	Serial string
}

type ScdKey struct {
	Serial      string
	Fingerprint string
	KeyGrip     string
	KeyId       string

	conn *ScdConn
}

func DialScd(path string) (*ScdConn, error) {
	conn, err := Dial(path)
	if err != nil {
		return nil, err
	}
	return &ScdConn{Conn: conn}, nil
}

// Invoke LEARN and return info about the keys in the token
func (s *ScdConn) Learn() ([]*ScdKey, error) {
	res, err := s.Conn.Transact("LEARN", func(inquiry string, lines []string) (string, error) {
		return "", nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate token: %w", err)
	}
	var keyids, keygrips []string
	fingerprints := make(map[string]string)
	for _, line := range res.Lines {
		parts := strings.Split(line, " ")
		switch parts[0] {
		case "SERIALNO":
			if len(parts) < 2 {
				continue
			}
			s.Serial = parts[1]
		case "KEYPAIRINFO":
			if len(parts) < 3 || parts[1] == "X" {
				continue
			}
			keygrips = append(keygrips, parts[1])
			keyids = append(keyids, parts[2])
		case "KEY-FPR":
			if len(parts) < 3 {
				continue
			}
			keyid := "OPENPGP." + parts[1]
			fingerprints[keyid] = parts[2]
		}
	}
	if len(keyids) == 0 {
		return nil, errors.New("failed to enumerate token: no valid key found")
	}
	infos := make([]*ScdKey, 0, len(keyids))
	dlog.Printf(3, "scdaemon token with serial %s has keys:", s.Serial)
	for i, keyid := range keyids {
		info := &ScdKey{
			conn:        s,
			Serial:      s.Serial,
			KeyId:       keyid,
			KeyGrip:     keygrips[i],
			Fingerprint: fingerprints[keyid],
		}
		dlog.Printf(3, " keyid=%s keygrip=%s fingerprint=%s", info.KeyId, info.KeyGrip, info.Fingerprint)
		infos = append(infos, info)
	}
	return infos, nil
}

// Verify that the token can be unlocked with the given pin
func (s *ScdConn) CheckPin(pin string) error {
	if s.Serial == "" {
		infos, err := s.Learn()
		if err != nil {
			return err
		}
		s.Serial = infos[0].Serial
	}
	_, err := s.Conn.Transact("CHECKPIN "+s.Serial, func(inquiry string, lines []string) (string, error) {
		if strings.HasPrefix(inquiry, "NEEDPIN") {
			return pin + "\x00", nil
		} else {
			return "", fmt.Errorf("unexpected INQUIRE: %s", inquiry)
		}
	})
	if eres, ok := err.(Response); ok && strings.Contains(eres.StatusMessage, "Bad PIN") {
		return sigerrors.PinIncorrectError{}
	} else if err != nil {
		return fmt.Errorf("failed to validate PIN: %w", err)
	}
	return nil
}

// Get the public key from the token
func (k *ScdKey) Public() (crypto.PublicKey, error) {
	res, err := k.conn.Transact("READKEY "+k.KeyId, nil)
	if err != nil {
		return nil, err
	}
	exp, err := parseCsExp(res.Blob)
	if err != nil {
		return nil, err
	}
	if len(exp.Items) != 1 {
		return nil, errors.New("invalid public key in token")
	}
	exp = exp.Items[0]
	if len(exp.Items) != 2 || !bytes.Equal(exp.Items[0].Value, []byte("public-key")) {
		return nil, errors.New("invalid public key in token")
	}
	exp = exp.Items[1]
	if len(exp.Items) == 0 {
		return nil, errors.New("invalid public key in token")
	}
	keyType := string(exp.Items[0].Value)
	values := make(map[string][]byte)
	for _, item := range exp.Items[1:] {
		if len(item.Items) != 2 {
			return nil, errors.New("invalid public key in token")
		}
		name := string(item.Items[0].Value)
		value := item.Items[1].Value
		values[name] = value
	}
	switch keyType {
	case "rsa":
		n := values["n"]
		e := values["e"]
		if n == nil || e == nil {
			return nil, errors.New("invalid RSA public key in token")
		}
		return &rsa.PublicKey{
			N: new(big.Int).SetBytes(n),
			E: int(new(big.Int).SetBytes(e).Int64()),
		}, nil
	default:
		return nil, fmt.Errorf("unsupported public key of type %s in token", keyType)
	}
}

// Create a signature over the given (unpadded) digest.
func (k *ScdKey) Sign(hashValue []byte, opts crypto.SignerOpts, pin string) ([]byte, error) {
	if opts == nil || opts.HashFunc() == 0 {
		return nil, errors.New("Signer options are required")
	} else if _, ok := opts.(*rsa.PSSOptions); ok {
		return nil, errors.New("RSA-PSS not implemented")
	}
	hashName := x509tools.HashNames[opts.HashFunc()]
	if hashName == "" {
		return nil, errors.New("unsupported hash algorithm")
	}
	hashName = strings.ToLower(strings.ReplaceAll(hashName, "-", ""))
	res, err := k.conn.Transact(fmt.Sprintf("SETDATA %X", hashValue), nil)
	if err != nil {
		return nil, err
	}
	res, err = k.conn.Transact(fmt.Sprintf("PKSIGN --hash=%s %s\n", hashName, k.KeyId),
		func(inquiry string, lines []string) (string, error) {
			if strings.HasPrefix(inquiry, "NEEDPIN") {
				return pin + "\x00", nil
			} else {
				return "", fmt.Errorf("unexpected INQUIRE: %s", inquiry)
			}
		})
	if eres, ok := err.(Response); ok && strings.Contains(eres.StatusMessage, "Bad PIN") {
		return nil, sigerrors.PinIncorrectError{}
	} else if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}
	return res.Blob, nil
}
