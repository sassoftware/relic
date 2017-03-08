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

package main

import (
	"gerrit-pdt.unx.sas.com/tools/relic.git/cmdline/shared"

	_ "gerrit-pdt.unx.sas.com/tools/relic.git/cmdline/remotecmd"
	_ "gerrit-pdt.unx.sas.com/tools/relic.git/cmdline/servecmd"
	_ "gerrit-pdt.unx.sas.com/tools/relic.git/cmdline/verify"

	_ "gerrit-pdt.unx.sas.com/tools/relic.git/signers/appmanifest"
	_ "gerrit-pdt.unx.sas.com/tools/relic.git/signers/cab"
	_ "gerrit-pdt.unx.sas.com/tools/relic.git/signers/cat"
	_ "gerrit-pdt.unx.sas.com/tools/relic.git/signers/deb"
	_ "gerrit-pdt.unx.sas.com/tools/relic.git/signers/jar"
	_ "gerrit-pdt.unx.sas.com/tools/relic.git/signers/msi"
	_ "gerrit-pdt.unx.sas.com/tools/relic.git/signers/pecoff"
	_ "gerrit-pdt.unx.sas.com/tools/relic.git/signers/pgp"
	_ "gerrit-pdt.unx.sas.com/tools/relic.git/signers/pkcs"
	_ "gerrit-pdt.unx.sas.com/tools/relic.git/signers/ps"
	_ "gerrit-pdt.unx.sas.com/tools/relic.git/signers/rpm"
)

func main() {
	shared.Main()
}
