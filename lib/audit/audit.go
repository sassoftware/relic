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

package audit

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/openpgp"

	"github.com/rs/zerolog"
	"github.com/sassoftware/relic/v7/lib/pgptools"
	"github.com/sassoftware/relic/v7/lib/pkcs9"
	"github.com/sassoftware/relic/v7/lib/x509tools"
)

type Info struct {
	Attributes map[string]interface{}
	StartTime  time.Time
}

// Create a new audit record, starting with the given key name, signature type,
// and digest
func New(keyName, sigType string, hash crypto.Hash) *Info {
	now := time.Now().UTC()
	a := make(map[string]interface{})
	a["sig.type"] = sigType
	a["sig.keyname"] = keyName
	a["sig.hash"] = x509tools.HashNames[hash]
	a["sig.timestamp"] = now
	if hostname, _ := os.Hostname(); hostname != "" {
		a["sig.hostname"] = hostname
	}
	return &Info{Attributes: a, StartTime: now}
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

// Marshal the audit record to JSON
func (info *Info) Marshal() ([]byte, error) {
	if info.Attributes["perf.elapsed.ms"] == nil && !info.StartTime.IsZero() {
		info.Attributes["perf.elapsed.ms"] = time.Since(info.StartTime).Nanoseconds() / 1e6
	}
	return json.Marshal(info.Attributes)
}

func (info *Info) AttrsForLog(prefix string) *zerolog.Event {
	ev := zerolog.Dict()
	for name, value := range info.Attributes {
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		name = name[len(prefix):]
		if s, ok := value.(string); ok {
			ev.Str(name, s)
		} else {
			ev.Interface(name, s)
		}
	}
	return ev
}

// Parse audit data from a JSON blob
func Parse(blob []byte) (*Info, error) {
	if len(blob) == 0 {
		return nil, errors.New("missing attributes")
	}
	info := new(Info)
	if err := json.Unmarshal(blob, &info.Attributes); err != nil {
		return nil, err
	}
	if sealed := info.Attributes["attributes"]; sealed != nil {
		blob, err := base64.StdEncoding.DecodeString(sealed.(string))
		if err != nil {
			return nil, err
		}
		info.Attributes = nil
		if err := json.Unmarshal(blob, &info.Attributes); err != nil {
			return nil, err
		}
	}
	return info, nil
}
