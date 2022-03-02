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
	"crypto/rand"
	"encoding/hex"
	"io"
	"math/big"
	"strings"
)

func makeKeyID() []byte {
	keyID := make([]byte, 20)
	if _, err := io.ReadFull(rand.Reader, keyID); err != nil {
		return nil
	}
	return keyID
}

func parseKeyID(value string) ([]byte, error) {
	return hex.DecodeString(strings.ReplaceAll(value, ":", ""))
}

func bytesToBig(val []byte) *big.Int {
	return new(big.Int).SetBytes(val)
}
