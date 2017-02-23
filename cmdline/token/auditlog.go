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
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"strings"
	"time"

	"gerrit-pdt.unx.sas.com/tools/relic.git/cmdline/shared"
	"gerrit-pdt.unx.sas.com/tools/relic.git/config"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/pgptools"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/pkcs7"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/x509tools"
	"gerrit-pdt.unx.sas.com/tools/relic.git/p11token"
	"github.com/spf13/cobra"
	"github.com/streadway/amqp"
	"golang.org/x/crypto/openpgp"
)

const (
	defaultSigXchg = "relic.signatures"
	sigKey         = "relic.signatures"
)

var argAuditAttrs []string

type auditAttributes map[string]interface{}

func NewAudit(key *p11token.Key, sigType string, hash crypto.Hash) auditAttributes {
	a := make(auditAttributes)
	a["sig.type"] = sigType
	a["sig.keyname"] = key.Name
	a["sig.hash"] = x509tools.HashNames[hash]
	a["sig.timestamp"] = time.Now().UTC()
	if hostname, _ := os.Hostname(); hostname != "" {
		a["sig.hostname"] = hostname
	}
	if argFile != "" && argFile != "-" {
		a["client.filename"] = path.Base(argFile)
	}
	for _, attr := range argAuditAttrs {
		i := strings.Index(attr, "=")
		if i < 0 {
			i = len(attr)
			attr += "="
		}
		k, v := attr[:i], attr[i+1:]
		a[k] = v
	}
	return a
}

func (a auditAttributes) SetPgpCert(entity *openpgp.Entity) {
	a["sig.pgp.fingerprint"] = fmt.Sprintf("%x", entity.PrimaryKey.Fingerprint[:])
	a["sig.pgp.entity"] = pgptools.EntityName(entity)
}

func (a auditAttributes) SetX509Cert(cert *x509.Certificate) {
	a["sig.x509.subject"] = x509tools.FormatRDNSequence(cert.Subject.ToRDNSequence())
	a["sig.x509.issuer"] = x509tools.FormatRDNSequence(cert.Issuer.ToRDNSequence())
	d := crypto.SHA1.New()
	d.Write(cert.Raw)
	a["sig.x509.fingerprint"] = fmt.Sprintf("%x", d.Sum(nil))
}

func (a auditAttributes) SetTimestamp(t time.Time) {
	a["sig.timestamp"] = t.UTC()
}

func sealAttributes(aconf *config.AmqpConfig, blob []byte) ([]byte, error) {
	doc := map[string][]byte{"attributes": blob, "seal": nil}
	if aconf.SealingKey != "" {
		sealKey, err := openKey(aconf.SealingKey)
		if err != nil {
			return nil, err
		}
		sealCerts, err := readCerts(sealKey)
		if err != nil {
			return nil, err
		}
		hash := crypto.SHA256
		d := hash.New()
		d.Write(blob)
		builder := pkcs7.NewBuilder(sealKey, sealCerts, hash)
		if err := builder.SetDetachedContent(pkcs7.OidData, d.Sum(nil)); err != nil {
			return nil, err
		}
		if err := builder.AddAuthenticatedAttribute(pkcs7.OidAttributeSigningTime, time.Now().UTC()); err != nil {
			return nil, err
		}
		psd, err := builder.Sign()
		if err != nil {
			return nil, err
		}
		sealblob, err := asn1.Marshal(*psd)
		if err != nil {
			return nil, err
		}
		doc["seal"] = sealblob
	}
	return json.Marshal(doc)
}

func sendAudit(aconf *config.AmqpConfig, blob []byte) error {
	msg := amqp.Publishing{
		DeliveryMode: amqp.Persistent,
		Timestamp:    time.Now(),
		ContentType:  "application/json",
		Body:         blob,
	}
	conn, err := amqp.Dial(aconf.Url)
	if err != nil {
		return err
	}
	defer conn.Close()
	ch, err := conn.Channel()
	if err != nil {
		return err
	}
	defer ch.Close()
	exName := aconf.SigsXchg
	if exName == "" {
		exName = defaultSigXchg
	}
	if err := ch.ExchangeDeclare(exName, "fanout", true, false, false, false, nil); err != nil {
		return err
	}
	ch.Confirm(false)
	notify := ch.NotifyPublish(make(chan amqp.Confirmation, 1))
	if err := ch.Publish(exName, sigKey, false, false, msg); err != nil {
		return err
	}
	confirm := <-notify
	if !confirm.Ack {
		return errors.New("message was NACKed")
	}
	return nil
}

func (a auditAttributes) Commit() error {
	if err := shared.InitConfig(); err != nil {
		return err
	}
	aconf := shared.CurrentConfig.Amqp
	if aconf == nil || aconf.Url == "" {
		// not enabled
		return nil
	}
	blob, err := json.Marshal(a)
	if err != nil {
		return fmt.Errorf("failed to seal audit log: %s", err)
	}
	fmt.Println(string(blob))
	blob, err = sealAttributes(aconf, blob)
	if err != nil {
		return fmt.Errorf("failed to seal audit log: %s", err)
	}
	if err := sendAudit(aconf, blob); err != nil {
		return fmt.Errorf("failed to send audit log: %s", err)
	}
	return nil
}

func addAuditFlags(cmd *cobra.Command) {
	cmd.Flags().StringArrayVar(&argAuditAttrs, "attr", nil, "")
	cmd.Flags().MarkHidden("attr")
}
