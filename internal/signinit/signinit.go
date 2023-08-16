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

package signinit

import (
	"context"
	"crypto"
	"fmt"
	"time"

	"github.com/sassoftware/relic/v7/cmdline/shared"
	"github.com/sassoftware/relic/v7/config"
	"github.com/sassoftware/relic/v7/lib/audit"
	"github.com/sassoftware/relic/v7/lib/certloader"
	"github.com/sassoftware/relic/v7/signers"
	"github.com/sassoftware/relic/v7/signers/sigerrors"
	"github.com/sassoftware/relic/v7/token"
)

// InitKey loads the cert chain for a key
func InitKey(ctx context.Context, tok token.Token, keyName string) (*certloader.Certificate, *config.KeyConfig, error) {
	key, err := tok.GetKey(ctx, keyName)
	if err != nil {
		return nil, nil, err
	}
	kconf := key.Config()
	// parse certificates
	cert, err := certloader.LoadTokenCertificates(key, kconf.X509Certificate, kconf.PgpCertificate, key.Certificate())
	if err != nil {
		return nil, nil, err
	}
	cert.KeyName = keyName
	return cert, kconf, nil
}

// InitKey prepares to sign using the named key, preparing a cert chain and
// signing options according to the server configuration
func Init(ctx context.Context, mod *signers.Signer, tok token.Token, keyName string, hash crypto.Hash, flags *signers.FlagValues) (*certloader.Certificate, *signers.SignOpts, error) {
	cert, kconf, err := InitKey(ctx, tok, keyName)
	if err != nil {
		return nil, nil, err
	}
	// create audit info
	auditInfo := audit.New(kconf.Name(), mod.Name, hash)
	now := time.Now().UTC()
	auditInfo.SetTimestamp(now)
	if cert.Leaf != nil {
		auditInfo.SetX509Cert(cert.Leaf)
	} else if mod.CertTypes&signers.CertTypeX509 != 0 {
		return nil, nil, sigerrors.ErrNoCertificate{Type: "x509"}
	}
	if cert.PgpKey != nil {
		auditInfo.SetPgpCert(cert.PgpKey)
	} else if mod.CertTypes&signers.CertTypePgp != 0 {
		return nil, nil, sigerrors.ErrNoCertificate{Type: "pgp"}
	}
	if kconf.Timestamp && !flags.GetBool("no-timestamp") {
		cert.Timestamper, err = GetTimestamper()
		if err != nil {
			return nil, nil, err
		}
	}
	opts := signers.SignOpts{
		Hash:  hash,
		Time:  now,
		Audit: auditInfo,
		Flags: flags,
	}
	opts = opts.WithContext(ctx)
	return cert, &opts, nil
}

func PublishAudit(info *audit.Info) error {
	aconf := shared.CurrentConfig.Amqp
	if aconf != nil && aconf.URL != "" {
		if err := info.Publish(aconf); err != nil {
			return fmt.Errorf("failed to publish audit log: %w", err)
		}
	}
	return nil
}
