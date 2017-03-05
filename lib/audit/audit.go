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

package audit

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"gerrit-pdt.unx.sas.com/tools/relic.git/config"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/certloader"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/pgptools"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/pkcs7"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/x509tools"
	"github.com/streadway/amqp"
	"golang.org/x/crypto/openpgp"
)

type AuditInfo struct {
	Attributes   map[string]interface{}
	sealed, seal []byte
}

type sealedDoc struct {
	Attributes []byte `json:"attributes"`
	Seal       []byte `json:"seal"`
}

func New(keyName, sigType string, hash crypto.Hash) *AuditInfo {
	a := make(map[string]interface{})
	a["sig.type"] = sigType
	a["sig.keyname"] = keyName
	a["sig.hash"] = x509tools.HashNames[hash]
	a["sig.timestamp"] = time.Now().UTC()
	if hostname, _ := os.Hostname(); hostname != "" {
		a["sig.hostname"] = hostname
	}
	for _, env := range os.Environ() {
		if !strings.HasPrefix(env, "RELIC_ATTR_") {
			continue
		}
		env = env[11:]
		i := strings.Index(env, "=")
		if i < 0 {
			continue
		}
		k, v := env[:i], env[i+1:]
		a[k] = v
	}
	return &AuditInfo{a, nil, nil}
}

func (info *AuditInfo) SetPgpCert(entity *openpgp.Entity) {
	info.Attributes["sig.pgp.fingerprint"] = fmt.Sprintf("%x", entity.PrimaryKey.Fingerprint[:])
	info.Attributes["sig.pgp.entity"] = pgptools.EntityName(entity)
}

func (info *AuditInfo) SetX509Cert(cert *x509.Certificate) {
	info.Attributes["sig.x509.subject"] = x509tools.FormatSubject(cert)
	info.Attributes["sig.x509.issuer"] = x509tools.FormatIssuer(cert)
	d := crypto.SHA1.New()
	d.Write(cert.Raw)
	info.Attributes["sig.x509.fingerprint"] = fmt.Sprintf("%x", d.Sum(nil))
}

func (info *AuditInfo) SetTimestamp(t time.Time) {
	info.Attributes["sig.timestamp"] = t.UTC()
}

func (info *AuditInfo) Seal(key crypto.Signer, certs []*x509.Certificate, hash crypto.Hash) error {
	blob, err := json.Marshal(info.Attributes)
	if err != nil {
		return err
	}
	d := hash.New()
	d.Write(blob)
	builder := pkcs7.NewBuilder(key, certs, hash)
	if err := builder.SetDetachedContent(pkcs7.OidData, d.Sum(nil)); err != nil {
		return err
	}
	if err := builder.AddAuthenticatedAttribute(pkcs7.OidAttributeSigningTime, time.Now().UTC()); err != nil {
		return err
	}
	psd, err := builder.Sign()
	if err != nil {
		return err
	}
	sealblob, err := asn1.Marshal(*psd)
	if err != nil {
		return err
	}
	info.sealed, err = json.Marshal(sealedDoc{blob, sealblob})
	return err
}

func (info *AuditInfo) Marshal() ([]byte, error) {
	if info.sealed != nil {
		return info.sealed, nil
	}
	blob, err := json.Marshal(info.Attributes)
	if err != nil {
		return nil, err
	}
	return json.Marshal(sealedDoc{blob, nil})
}

func (info *AuditInfo) GetSealed() ([]byte, []byte) {
	return info.sealed, info.seal
}

func (info *AuditInfo) Publish(aconf *config.AmqpConfig) error {
	blob, err := info.Marshal()
	if err != nil {
		return err
	}
	msg := amqp.Publishing{
		DeliveryMode: amqp.Persistent,
		Timestamp:    time.Now(),
		ContentType:  "application/json",
		Body:         blob,
	}
	conn, err := Connect(aconf)
	if err != nil {
		return err
	}
	defer conn.Close()
	ch, err := conn.Channel()
	if err != nil {
		return err
	}
	defer ch.Close()
	if err := ch.ExchangeDeclare(aconf.ExchangeName(), amqp.ExchangeFanout, true, false, false, false, nil); err != nil {
		return err
	}
	ch.Confirm(false)
	notify := ch.NotifyPublish(make(chan amqp.Confirmation, 1))
	if err := ch.Publish(aconf.ExchangeName(), aconf.RoutingKey(), false, false, msg); err != nil {
		return err
	}
	confirm := <-notify
	if !confirm.Ack {
		return errors.New("message was NACKed")
	}
	return nil
}

func Parse(blob []byte) (*AuditInfo, error) {
	var doc sealedDoc
	if err := json.Unmarshal(blob, &doc); err != nil {
		return nil, err
	}
	if len(doc.Attributes) == 0 {
		return nil, errors.New("missing attributes")
	}
	info := new(AuditInfo)
	info.sealed = doc.Attributes
	info.seal = doc.Seal
	err := json.Unmarshal(doc.Attributes, &info.Attributes)
	return info, err
}

func Connect(aconf *config.AmqpConfig) (*amqp.Connection, error) {
	uri, err := amqp.ParseURI(aconf.Url)
	if err != nil {
		return nil, err
	}
	var tconf *tls.Config
	var auth []amqp.Authentication
	if uri.Scheme == "amqps" {
		tconf = &tls.Config{}
		if aconf.CaCert != "" {
			if err := x509tools.LoadCertPool(aconf.CaCert, tconf); err != nil {
				return nil, err
			}
		}
		if aconf.CertFile != "" {
			cert, err := certloader.LoadX509KeyPair(aconf.CertFile, aconf.KeyFile)
			if err != nil {
				return nil, err
			}
			tconf.Certificates = []tls.Certificate{cert.TLS()}
		}
		x509tools.SetKeyLogFile(tconf)
		if len(tconf.Certificates) != 0 {
			auth = append(auth, externalAuth{})
		}
	}
	if uri.Password != "" {
		auth = append(auth, uri.PlainAuth())
	}
	qconf := amqp.Config{SASL: auth, TLSClientConfig: tconf}
	return amqp.DialConfig(aconf.Url, qconf)
}

type externalAuth struct{}

func (externalAuth) Mechanism() string { return "EXTERNAL" }
func (externalAuth) Response() string  { return "" }
