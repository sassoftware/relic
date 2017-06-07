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

package shared

import (
	"crypto"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

var ArgDigest string

const DefaultHash = "SHA-256"

func AddDigestFlag(cmd *cobra.Command) {
	cmd.Flags().StringVar(&ArgDigest, "digest", DefaultHash, "Specify a digest algorithm")
}

func GetDigest() (hash crypto.Hash, err error) {
	if ArgDigest == "" {
		// TODO: figure out why this randomly started coming back blank
		ArgDigest = DefaultHash
	}
	name := strings.ToLower(ArgDigest)
	name = strings.Replace(name, "-", "", -1)
	switch name {
	case "md5":
		hash = crypto.MD5
	case "sha1":
		hash = crypto.SHA1
	case "sha224":
		hash = crypto.SHA224
	case "sha256":
		hash = crypto.SHA256
	case "sha384":
		hash = crypto.SHA384
	case "sha512":
		hash = crypto.SHA512
	default:
		return hash, fmt.Errorf("unsupported digest \"%s\"", ArgDigest)
	}
	return hash, nil
}
