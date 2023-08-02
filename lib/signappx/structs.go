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

package signappx

import (
	"archive/zip"
	"crypto"

	"github.com/sassoftware/relic/v7/lib/authenticode"
	"github.com/sassoftware/relic/v7/lib/pkcs9"
)

const (
	appxSignature     = "AppxSignature.p7x"
	appxCodeIntegrity = "AppxMetadata/CodeIntegrity.cat"
	appxBlockMap      = "AppxBlockMap.xml"
	appxManifest      = "AppxManifest.xml"
	appxContentTypes  = "[Content_Types].xml"

	bundleManifestFile = "AppxMetadata/AppxBundleManifest.xml"
)

type AppxSignature struct {
	Signature         *pkcs9.TimestampedSignature
	Name, DisplayName string
	Version           string
	IsBundle          bool
	Hash              crypto.Hash
	HashValues        map[string][]byte
	Bundled           map[string]*AppxSignature
	OpusInfo          *authenticode.SpcSpOpusInfo
}

type zipFiles map[string]*zip.File
