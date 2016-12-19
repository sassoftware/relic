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

package token

import (
	"gerrit-pdt.unx.sas.com/tools/relic.git/cmdline/servecmd"
	"gerrit-pdt.unx.sas.com/tools/relic.git/cmdline/shared"
	"gerrit-pdt.unx.sas.com/tools/relic.git/p11token"
	"gerrit-pdt.unx.sas.com/tools/relic.git/server"
	"gerrit-pdt.unx.sas.com/tools/relic.git/signrpm"
)

func initHook(srv *server.Server) error {
	needKeys := shared.CurrentConfig.GetServedKeys()
	keyMap := make(map[string]*p11token.Key)
	for _, keyName := range needKeys {
		key, err := openKey(keyName)
		if err != nil {
			return err
		}
		keyMap[keyName] = key
	}
	signrpm.AddSignRpmHandler(srv, keyMap)
	return nil
}

func init() {
	servecmd.AddHook(initHook)
}
