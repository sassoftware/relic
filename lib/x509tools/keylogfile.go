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

package x509tools

import (
	"crypto/tls"
	"fmt"
	"os"
)

func SetKeyLogFile(tconf *tls.Config) {
	if klf := os.Getenv("SSLKEYLOGFILE"); klf != "" {
		fmt.Fprintln(os.Stderr, "WARNING: SSLKEYLOGFILE is set! TLS master secrets will be logged.")
		f, err := os.OpenFile(klf, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0600)
		if err != nil {
			panic(err)
		}
		tconf.KeyLogWriter = f
	}
}
