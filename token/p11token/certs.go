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

package p11token

import (
	"crypto/sha1"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/miekg/pkcs11"

	"github.com/sassoftware/relic/v7/signers/sigerrors"
)

var newCertAttrs = []*pkcs11.Attribute{
	pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
	pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
	pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, false),
	pkcs11.NewAttribute(pkcs11.CKA_CERTIFICATE_TYPE, pkcs11.CKC_X_509),
}

func (tk *Token) ImportCertificate(cert *x509.Certificate, labelBase string) error {
	fingerprint := sha1.Sum(cert.Raw)
	if labelBase == "" {
		return errors.New("label is required")
	}
	// make a label from the private key label plus the certificate fingerprint
	label := fmt.Sprintf("%s_chain_%x", labelBase, fingerprint[:8])
	tk.mutex.Lock()
	defer tk.mutex.Unlock()
	if err := tk.certExists(label); err != nil {
		return err
	}
	keyID := makeKeyID()
	if keyID == nil {
		return errors.New("failed to make key ID")
	}
	attrs := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_SUBJECT, cert.RawSubject),
		pkcs11.NewAttribute(pkcs11.CKA_ISSUER, cert.RawIssuer),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, cert.Raw),
	}
	attrs = append(attrs, newCertAttrs...)
	_, err := tk.ctx.CreateObject(tk.sh, attrs)
	return err
}

func (tk *Token) certExists(label string) error {
	attrs := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	}
	objects, err := tk.findObject(attrs)
	if err != nil {
		return err
	} else if len(objects) != 0 {
		return sigerrors.ErrExist
	} else {
		return nil
	}
}

func (key *Key) ImportCertificate(cert *x509.Certificate) error {
	keyID, handle, err := key.findCertificate()
	if err != nil {
		return err
	} else if handle != 0 {
		return sigerrors.ErrExist
	}
	label := key.getLabel()
	if label == "" {
		return errors.New("label is required")
	}
	attrs := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_SUBJECT, cert.RawSubject),
		pkcs11.NewAttribute(pkcs11.CKA_ISSUER, cert.RawIssuer),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, cert.Raw),
	}
	attrs = append(attrs, newCertAttrs...)
	key.token.mutex.Lock()
	defer key.token.mutex.Unlock()
	_, err = key.token.ctx.CreateObject(key.token.sh, attrs)
	return err
}

func (key *Key) findCertificate() (keyID []byte, handle pkcs11.ObjectHandle, err error) {
	keyID = key.GetID()
	if len(keyID) == 0 {
		return nil, 0, errors.New("no keyID")
	}
	key.token.mutex.Lock()
	defer key.token.mutex.Unlock()
	attrs := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
	}
	objects, err := key.token.findObject(attrs)
	if err != nil {
		return nil, 0, err
	}
	if len(objects) == 0 {
		return keyID, 0, nil
	}
	return keyID, objects[0], nil
}
