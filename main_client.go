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

package main

// Commands and signers for the basic client only (pure Go, all OSes)

import (
	"github.com/sassoftware/relic/cmdline/shared"

	_ "github.com/sassoftware/relic/cmdline/remotecmd"
	_ "github.com/sassoftware/relic/cmdline/verify"

	_ "github.com/sassoftware/relic/signers/apk"
	_ "github.com/sassoftware/relic/signers/appmanifest"
	_ "github.com/sassoftware/relic/signers/appx"
	_ "github.com/sassoftware/relic/signers/cab"
	_ "github.com/sassoftware/relic/signers/cat"
	_ "github.com/sassoftware/relic/signers/deb"
	_ "github.com/sassoftware/relic/signers/dmg"
	_ "github.com/sassoftware/relic/signers/jar"
	_ "github.com/sassoftware/relic/signers/macho"
	_ "github.com/sassoftware/relic/signers/msi"
	_ "github.com/sassoftware/relic/signers/pecoff"
	_ "github.com/sassoftware/relic/signers/pgp"
	_ "github.com/sassoftware/relic/signers/pkcs"
	_ "github.com/sassoftware/relic/signers/ps"
	_ "github.com/sassoftware/relic/signers/rpm"
	_ "github.com/sassoftware/relic/signers/starman"
	_ "github.com/sassoftware/relic/signers/vsix"
	_ "github.com/sassoftware/relic/signers/xap"
	_ "github.com/sassoftware/relic/signers/xar"
)

func main() {
	shared.Main()
}
