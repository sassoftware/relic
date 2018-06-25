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

	"github.com/sassoftware/relic/cmdline/shared"
	"github.com/sassoftware/relic/lib/audit"
	"github.com/sassoftware/relic/lib/certloader"
	"github.com/sassoftware/relic/lib/pkcs9/timestampcache"
	"github.com/sassoftware/relic/signers"
	"github.com/sassoftware/relic/signers/pkcs"
	"github.com/sassoftware/relic/signers/sigerrors"
	"github.com/sassoftware/relic/token"
)

func Init(ctx context.Context, mod *signers.Signer, tok token.Token, keyName string, hash crypto.Hash, flags *signers.FlagValues) (*certloader.Certificate, *signers.SignOpts, error) {
	var key token.Key
	var err error
	if tctx, ok := tok.(keyGetter); ok {
		key, err = tctx.GetKeyContext(ctx, keyName)
	} else {
		key, err = tok.GetKey(keyName)
	}
	if err != nil {
		return nil, nil, err
	}
	kconf := key.Config()
	// parse certificates
	var x509cert, pgpcert string
	if mod.CertTypes&signers.CertTypeX509 != 0 {
		if kconf.X509Certificate == "" {
			return nil, nil, sigerrors.ErrNoCertificate{"x509"}
		}
		x509cert = kconf.X509Certificate
	}
	if mod.CertTypes&signers.CertTypePgp != 0 {
		if kconf.PgpCertificate == "" {
			return nil, nil, sigerrors.ErrNoCertificate{"pgp"}
		}
		pgpcert = kconf.PgpCertificate
	}
	cert, err := certloader.LoadTokenCertificates(key, x509cert, pgpcert)
	if err != nil {
		return nil, nil, err
	}
	cert.KeyName = keyName
	// create audit info
	auditInfo := audit.New(keyName, mod.Name, hash)
	now := time.Now().UTC()
	auditInfo.SetTimestamp(now)
	if cert.Leaf != nil {
		auditInfo.SetX509Cert(cert.Leaf)
	}
	if cert.PgpKey != nil {
		auditInfo.SetPgpCert(cert.PgpKey)
	}
	if kconf.Timestamp {
		tsconf, err := shared.CurrentConfig.GetTimestampConfig()
		if err != nil {
			return nil, nil, err
		}
		cert.Timestamper = pkcs.Timestamper{Config: tsconf}
		if len(tsconf.Memcache) != 0 {
			cert.Timestamper, err = timestampcache.New(cert.Timestamper, tsconf.Memcache)
			if err != nil {
				return nil, nil, err
			}
		}
	}
	opts := &signers.SignOpts{
		Hash:  hash,
		Time:  now,
		Audit: auditInfo,
		Flags: flags,
	}
	return cert, opts, nil
}

func PublishAudit(info *audit.Info) error {
	aconf := shared.CurrentConfig.Amqp
	if aconf != nil && aconf.URL != "" {
		if err := info.Publish(aconf); err != nil {
			return fmt.Errorf("failed to publish audit log: %s", err)
		}
	}
	return nil
}

type keyGetter interface {
	GetKeyContext(context.Context, string) (token.Key, error)
}
