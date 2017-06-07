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

package token

import (
	"crypto"
	"fmt"
	"path/filepath"

	"github.com/sassoftware/relic/cmdline/shared"
	"github.com/sassoftware/relic/config"
	"github.com/sassoftware/relic/lib/audit"
	"github.com/sassoftware/relic/lib/certloader"
	"github.com/sassoftware/relic/token"
)

func NewAudit(key token.Key, sigType string, hash crypto.Hash) *audit.Info {
	info := audit.New(key.Config().Name(), sigType, hash)
	if argFile != "" && argFile != "-" && info.Attributes["client.filename"] == nil {
		info.Attributes["client.filename"] = filepath.Base(argFile)
	}
	return info
}

func PublishAudit(info *audit.Info) error {
	if err := shared.InitConfig(); err != nil {
		return err
	}
	aconf := shared.CurrentConfig.Amqp
	if aconf != nil && aconf.URL != "" {
		if aconf.SealingKey != "" {
			if err := sealAudit(info, aconf); err != nil {
				return shared.Fail(fmt.Errorf("failed to seal audit log: %s", err))
			}
		}
		if err := info.Publish(aconf); err != nil {
			return shared.Fail(fmt.Errorf("failed to publish audit log: %s", err))
		}
	}
	if err := info.WriteFd(); err != nil {
		return shared.Fail(fmt.Errorf("failed to publish audit log: %s", err))
	}
	return nil
}

func sealAudit(info *audit.Info, aconf *config.AmqpConfig) error {
	key, err := openKey(aconf.SealingKey)
	if err != nil {
		return err
	}
	cert, err := certloader.LoadTokenCertificates(key, key.Config().X509Certificate, "")
	if err != nil {
		return err
	}
	return info.Seal(cert.Signer(), cert.Chain(), crypto.SHA256)
}
