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
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/miekg/pkcs11"

	"github.com/sassoftware/relic/v7/lib/x509tools"
	"github.com/sassoftware/relic/v7/token"
)

var classNames = map[uint]string{
	pkcs11.CKO_DATA:              "data",
	pkcs11.CKO_CERTIFICATE:       "certificate",
	pkcs11.CKO_PUBLIC_KEY:        "public_key",
	pkcs11.CKO_PRIVATE_KEY:       "private_key",
	pkcs11.CKO_SECRET_KEY:        "secret_key",
	pkcs11.CKO_HW_FEATURE:        "hw_feature",
	pkcs11.CKO_DOMAIN_PARAMETERS: "domain_parameters",
	pkcs11.CKO_MECHANISM:         "mechanism",
	pkcs11.CKO_OTP_KEY:           "otp_key",
}

var keyTypes = map[uint]string{
	pkcs11.CKK_RSA: "rsa",
	pkcs11.CKK_DSA: "dsa",
	pkcs11.CKK_EC:  "ec",
}

func (tok *Token) ListKeys(opts token.ListOptions) (err error) {
	filterKeyId, err := parseKeyID(opts.ID)
	if err != nil {
		return errors.New("invalid filter id")
	}
	tok.mutex.Lock()
	defer tok.mutex.Unlock()
	if err := tok.ctx.FindObjectsInit(tok.sh, nil); err != nil {
		return err
	}
	defer func() {
		err2 := tok.ctx.FindObjectsFinal(tok.sh)
		if err2 != nil && err == nil {
			err = err2
		}
	}()
	for {
		objects, _, err := tok.ctx.FindObjects(tok.sh, 1)
		if err != nil {
			return err
		} else if len(objects) == 0 {
			break
		}
		for _, handle := range objects {
			objId := tok.getAttribute(handle, pkcs11.CKA_ID)
			label := tok.getAttribute(handle, pkcs11.CKA_LABEL)
			if opts.Label != "" && string(label) != opts.Label {
				continue
			}
			if len(filterKeyId) != 0 && !bytes.Equal(filterKeyId, objId) {
				continue
			}
			fmt.Fprintf(opts.Output, "handle 0x%08x:\n", handle)
			rawClass := tok.getAttribute(handle, pkcs11.CKA_CLASS)
			class, err := getUlong(rawClass)
			if name := classNames[class]; name != "" && err == nil {
				fmt.Fprintf(opts.Output, " class:   %s\n", name)
			} else {
				fmt.Fprintf(opts.Output, " class:   0x%x\n", rawClass)
			}
			if len(objId) > 0 {
				fmt.Fprintf(opts.Output, " id:      %s\n", formatKeyID(objId))
			}
			if len(label) > 0 {
				fmt.Fprintf(opts.Output, " label:   %s\n", label)
			}
			switch class {
			case pkcs11.CKO_PUBLIC_KEY:
				tok.printKey(opts, handle)
			case pkcs11.CKO_PRIVATE_KEY:
				tok.printKey(opts, handle)
			case pkcs11.CKO_CERTIFICATE:
				tok.printCertificate(opts, handle)
			case pkcs11.CKO_DATA:
				value := tok.getAttribute(handle, pkcs11.CKA_VALUE)
				fmt.Fprintf(opts.Output, " size:    %d\n", len(value))
				if opts.Values {
					fmt.Fprintln(opts.Output, " value: !!binary |")
					dumpData(opts.Output, value)
				}
			}
			fmt.Fprintln(opts.Output)
		}
	}
	return nil
}

func (tok *Token) printKey(opts token.ListOptions, handle pkcs11.ObjectHandle) {
	rawKeyType := tok.getAttribute(handle, pkcs11.CKA_KEY_TYPE)
	keyType, err := getUlong(rawKeyType)
	if name := keyTypes[keyType]; name != "" && err == nil {
		fmt.Fprintf(opts.Output, " type:    %s\n", name)
	} else {
		fmt.Fprintf(opts.Output, " type:    0x%x\n", keyType)
	}
	switch keyType {
	case pkcs11.CKK_RSA:
		if n := tok.getAttribute(handle, pkcs11.CKA_MODULUS); len(n) != 0 {
			fmt.Fprintf(opts.Output, " bits:    %d\n", len(n)*8)
			if opts.Values {
				fmt.Fprintf(opts.Output, " n:       0x%x\n", bytesToBig(n))
			}
		}
		if e := tok.getAttribute(handle, pkcs11.CKA_PUBLIC_EXPONENT); len(e) != 0 && opts.Values {
			fmt.Fprintf(opts.Output, " e:       %s\n", bytesToBig(e))
		}
	case pkcs11.CKK_EC:
		ecparams := tok.getAttribute(handle, pkcs11.CKA_EC_PARAMS)
		if len(ecparams) == 0 {
			return
		}
		curve, err := x509tools.CurveByDer(ecparams)
		if err != nil {
			fmt.Fprintf(opts.Output, " curve:   %x\n", ecparams)
			return
		}
		fmt.Fprintf(opts.Output, " bits:    %d\n", curve.Bits)
		ecpoint := tok.getAttribute(handle, pkcs11.CKA_EC_POINT)
		if len(ecpoint) > 0 && opts.Values {
			x, y := x509tools.DerToPoint(curve.Curve, ecpoint)
			if x != nil {
				fmt.Fprintf(opts.Output, " x:       0x%x\n", x)
				fmt.Fprintf(opts.Output, " y:       0x%x\n", y)
			}
		}
	}
}

func (tok *Token) printCertificate(opts token.ListOptions, handle pkcs11.ObjectHandle) {
	blob := tok.getAttribute(handle, pkcs11.CKA_VALUE)
	if len(blob) == 0 {
		fmt.Fprintln(opts.Output, "certificate is missing")
		return
	}
	cert, err := x509.ParseCertificate(blob)
	if err != nil {
		fmt.Fprintln(opts.Output, "certificate is invalid:", err)
	}
	d := crypto.SHA1.New()
	d.Write(blob)
	fmt.Fprintf(opts.Output, " subject: %s\n issuer:  %s\n sha1:    %x\n", x509tools.FormatSubject(cert), x509tools.FormatIssuer(cert), d.Sum(nil))
	if opts.Values {
		fmt.Fprintln(opts.Output, " value: |\n  -----BEGIN CERTIFICATE-----")
		dumpData(opts.Output, blob)
		fmt.Fprintln(opts.Output, "  -----END CERTIFICATE-----")
	}
}

func formatKeyID(keyID []byte) string {
	chunks := make([]string, len(keyID))
	for i, j := range keyID {
		chunks[i] = fmt.Sprintf("%02x", j)
	}
	return strings.Join(chunks, ":")
}

func dumpData(w io.Writer, d []byte) {
	encoded := base64.StdEncoding.EncodeToString(d)
	for len(encoded) > 0 {
		n := 64
		if n > len(encoded) {
			n = len(encoded)
		}
		fmt.Fprintln(w, " ", encoded[:n])
		encoded = encoded[n:]
	}
}
