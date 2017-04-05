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
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/pgptools"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/pkcs7"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/pkcs9"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/x509tools"
	"golang.org/x/crypto/openpgp"
)

const EnvAuditFd = "RELIC_AUDIT_FD"

type Info struct {
	Attributes   map[string]interface{}
	sealed, seal []byte
}

type sealedDoc struct {
	Attributes []byte `json:"attributes"`
	Seal       []byte `json:"seal"`
}

// Create a new audit record, starting with the given key name, signature type,
// and digest
func New(keyName, sigType string, hash crypto.Hash) *Info {
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
	return &Info{a, nil, nil}
}

// Set a PGP certificate for this audit record
func (info *Info) SetPgpCert(entity *openpgp.Entity) {
	info.Attributes["sig.pgp.fingerprint"] = fmt.Sprintf("%x", entity.PrimaryKey.Fingerprint[:])
	info.Attributes["sig.pgp.entity"] = pgptools.EntityName(entity)
}

// Set a X509 certificate for this audit record
func (info *Info) SetX509Cert(cert *x509.Certificate) {
	info.Attributes["sig.x509.subject"] = x509tools.FormatSubject(cert)
	info.Attributes["sig.x509.issuer"] = x509tools.FormatIssuer(cert)
	d := crypto.SHA1.New()
	d.Write(cert.Raw)
	info.Attributes["sig.x509.fingerprint"] = fmt.Sprintf("%x", d.Sum(nil))
}

// Override the default timestamp for this audit record
func (info *Info) SetTimestamp(t time.Time) {
	info.Attributes["sig.timestamp"] = t.UTC()
}

// Add a PKCS#9 timestamp (counter-signature) to this audit record
func (info *Info) SetCounterSignature(cs *pkcs9.CounterSignature) {
	if cs == nil {
		return
	}
	info.Attributes["sig.ts.timestamper"] = x509tools.FormatSubject(cs.Certificate)
	info.Attributes["sig.ts.timestamp"] = cs.SigningTime
	info.Attributes["sig.ts.hash"] = x509tools.HashNames[cs.Hash]
}

// Set the MIME type (Content-Type) that the server will use when returning a
// result to the client. This is not the MIME type of the package being signed.
func (info *Info) SetMimeType(mimeType string) {
	info.Attributes["content-type"] = mimeType
}

// Get the MIME type that the server will use when returning a result to the
// client. This is not the MIME type of the package being signed.
func (info *Info) GetMimeType() string {
	v := info.Attributes["content-type"]
	if v != nil {
		return v.(string)
	}
	return "application/octet-stream"
}

// Seal the audit record by signing it with a key
func (info *Info) Seal(key crypto.Signer, certs []*x509.Certificate, hash crypto.Hash) error {
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
	sealblob, err := psd.Marshal()
	if err != nil {
		return err
	}
	info.sealed, err = json.Marshal(sealedDoc{blob, sealblob})
	return err
}

// Marshal the possibly-sealed audit record to JSON
func (info *Info) Marshal() ([]byte, error) {
	if info.sealed != nil {
		return info.sealed, nil
	}
	blob, err := json.Marshal(info.Attributes)
	if err != nil {
		return nil, err
	}
	return json.Marshal(sealedDoc{blob, nil})
}

// Get previously parsed, marshalled JSON data
func (info *Info) GetSealed() ([]byte, []byte) {
	return info.sealed, info.seal
}

// Parse audit data from a JSON blob
func Parse(blob []byte) (*Info, error) {
	if len(blob) == 0 {
		return nil, errors.New("missing attributes")
	}
	var doc sealedDoc
	if err := json.Unmarshal(blob, &doc); err != nil {
		return nil, err
	}
	if len(doc.Attributes) == 0 {
		return nil, errors.New("missing attributes")
	}
	info := new(Info)
	info.sealed = doc.Attributes
	info.seal = doc.Seal
	err := json.Unmarshal(doc.Attributes, &info.Attributes)
	return info, err
}
