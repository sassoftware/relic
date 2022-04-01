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

	"github.com/spf13/cobra"

	"github.com/sassoftware/relic/v7/lib/x509tools"
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
	hash = x509tools.HashByName(ArgDigest)
	if hash == 0 {
		err = fmt.Errorf("unsupported digest \"%s\"", ArgDigest)
	}
	return hash, err
}
