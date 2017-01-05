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

package x509tools

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var (
	ArgSelfSign           bool
	ArgCountry            string
	ArgOrganization       string
	ArgOrganizationalUnit string
	ArgLocality           string
	ArgProvince           string
	ArgCommonName         string
	ArgDnsNames           string
	ArgEmailNames         string
	ArgKeyUsage           string
	ArgExpireDays         uint
)

func AddRequestFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&ArgCountry, "countryName", "", "Subject name")
	cmd.Flags().StringVar(&ArgProvince, "stateOrProvinceName", "", "Subject name")
	cmd.Flags().StringVar(&ArgLocality, "localityName", "", "Subject name")
	cmd.Flags().StringVar(&ArgOrganization, "organizationName", "", "Subject name")
	cmd.Flags().StringVar(&ArgOrganizationalUnit, "organizationalUnitName", "", "Subject name")
	cmd.Flags().StringVarP(&ArgCommonName, "commonName", "n", "", "Subject commonName")
	cmd.Flags().StringVar(&ArgDnsNames, "alternate-dns", "", "DNS subject alternate name (comma or space separated)")
	cmd.Flags().StringVar(&ArgEmailNames, "alternate-email", "", "Email subject alternate name (comma or space separated)")
}

func AddCertFlags(cmd *cobra.Command) {
	AddRequestFlags(cmd)
	cmd.Flags().StringVarP(&ArgKeyUsage, "key-usage", "U", "", "Key usage, one of: serverAuth clientAuth codeSigning emailProtection")
	cmd.Flags().UintVarP(&ArgExpireDays, "expire-days", "e", 36525, "Number of days before certificate expires")
}

func splitAndTrim(s string) []string {
	if s == "" {
		return nil
	}
	s = strings.Replace(s, ",", " ", -1)
	pieces := strings.Split(s, " ")
	ret := make([]string, 0, len(pieces))
	for _, p := range pieces {
		p = strings.Trim(p, " ")
		if p != "" {
			ret = append(ret, p)
		}
	}
	return ret
}

func subjName() (name pkix.Name) {
	if ArgCountry != "" {
		name.Country = []string{ArgCountry}
	}
	if ArgProvince != "" {
		name.Province = []string{ArgProvince}
	}
	if ArgLocality != "" {
		name.Locality = []string{ArgLocality}
	}
	if ArgOrganization != "" {
		name.Organization = []string{ArgOrganization}
	}
	if ArgOrganizationalUnit != "" {
		name.OrganizationalUnit = []string{ArgOrganizationalUnit}
	}
	name.CommonName = ArgCommonName
	return
}

func setUsage(template *x509.Certificate) error {
	usage := x509.KeyUsageDigitalSignature
	var extended x509.ExtKeyUsage
	switch strings.ToLower(ArgKeyUsage) {
	case "serverauth":
		usage |= x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement
		extended = x509.ExtKeyUsageServerAuth
	case "clientauth":
		usage |= x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement
		extended = x509.ExtKeyUsageClientAuth
	case "codesigning":
		extended = x509.ExtKeyUsageCodeSigning
	case "emailprotection":
		usage |= x509.KeyUsageContentCommitment | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement
		extended = x509.ExtKeyUsageEmailProtection
	case "":
		return nil
	default:
		return errors.New("invalid key-usage")
	}
	template.KeyUsage = usage
	template.ExtKeyUsage = []x509.ExtKeyUsage{extended}
	return nil
}

func MakeRequest(rand io.Reader, key crypto.Signer) (string, error) {
	var template x509.CertificateRequest
	template.Subject = subjName()
	template.DNSNames = splitAndTrim(ArgDnsNames)
	template.EmailAddresses = splitAndTrim(ArgEmailNames)
	template.SignatureAlgorithm = X509SignatureAlgorithm(key.Public())
	csr, err := x509.CreateCertificateRequest(rand, &template, key)
	if err != nil {
		return "", err
	}
	block := &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}
	return string(pem.EncodeToMemory(block)), nil
}

func MakeCertificate(rand io.Reader, key crypto.Signer) (string, error) {
	var template x509.Certificate
	template.SerialNumber = MakeSerial()
	if template.SerialNumber == nil {
		return "", errors.New("Failed to generate a serial number")
	}
	template.Subject = subjName()
	template.DNSNames = splitAndTrim(ArgDnsNames)
	template.EmailAddresses = splitAndTrim(ArgEmailNames)
	template.SignatureAlgorithm = X509SignatureAlgorithm(key.Public())
	template.NotBefore = time.Now().Add(time.Hour * -24)
	template.NotAfter = time.Now().Add(time.Hour * 24 * time.Duration(ArgExpireDays))
	template.IsCA = true
	template.BasicConstraintsValid = true
	if err := setUsage(&template); err != nil {
		return "", err
	}
	template.Issuer = template.Subject
	if ski, err := SubjectKeyId(key.Public()); err != nil {
		return "", err
	} else {
		template.SubjectKeyId = ski
	}
	cert, err := x509.CreateCertificate(rand, &template, &template, key.Public(), key)
	if err != nil {
		return "", err
	}
	block := &pem.Block{Type: "CERTIFICATE", Bytes: cert}
	return string(pem.EncodeToMemory(block)), nil
}
