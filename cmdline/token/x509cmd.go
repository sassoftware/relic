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
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"gerrit-pdt.unx.sas.com/tools/relic.git/cmdline/shared"
	"gerrit-pdt.unx.sas.com/tools/relic.git/p11token"
	"github.com/spf13/cobra"
)

var ReqCmd = &cobra.Command{
	Use:   "x509-request",
	Short: "Generate PKCS#10 certificate signing request",
}

var SelfSignCmd = &cobra.Command{
	Use:   "x509-self-sign",
	Short: "Generate self-signed X509 certificate",
}

var (
	argSelfSign           bool
	argCountry            string
	argOrganization       string
	argOrganizationalUnit string
	argLocality           string
	argProvince           string
	argCommonName         string
	argDnsNames           string
	argEmailNames         string
	argKeyUsage           string
	argExpireDays         uint
)

func init() {
	ReqCmd.RunE = x509Cmd
	shared.RootCmd.AddCommand(ReqCmd)
	addSelectOrGenerateFlags(ReqCmd)
	addCertFlags(ReqCmd)

	SelfSignCmd.RunE = x509Cmd
	shared.RootCmd.AddCommand(SelfSignCmd)
	SelfSignCmd.Flags().StringVarP(&argKeyUsage, "key-usage", "U", "", "Key usage, one of: serverAuth clientAuth codeSigning emailProtection")
	SelfSignCmd.Flags().UintVarP(&argExpireDays, "expire-days", "e", 36525, "Number of days before certificate expires")
	addSelectOrGenerateFlags(SelfSignCmd)
	addCertFlags(SelfSignCmd)
}

func addCertFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&argCountry, "countryName", "", "Subject name")
	cmd.Flags().StringVar(&argProvince, "stateOrProvinceName", "", "Subject name")
	cmd.Flags().StringVar(&argLocality, "localityName", "", "Subject name")
	cmd.Flags().StringVar(&argOrganization, "organizationName", "", "Subject name")
	cmd.Flags().StringVar(&argOrganizationalUnit, "organizationalUnitName", "", "Subject name")
	cmd.Flags().StringVarP(&argCommonName, "commonName", "n", "", "Subject commonName")
	cmd.Flags().StringVar(&argDnsNames, "alternate-dns", "", "DNS subject alternate name (comma or space separated)")
	cmd.Flags().StringVar(&argEmailNames, "alternate-email", "", "Email subject alternate name (comma or space separated)")
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
	if argCountry != "" {
		name.Country = []string{argCountry}
	}
	if argProvince != "" {
		name.Province = []string{argProvince}
	}
	if argLocality != "" {
		name.Locality = []string{argLocality}
	}
	if argOrganization != "" {
		name.Organization = []string{argOrganization}
	}
	if argOrganizationalUnit != "" {
		name.OrganizationalUnit = []string{argOrganizationalUnit}
	}
	name.CommonName = argCommonName
	return
}

func makeSerial() *big.Int {
	blob := make([]byte, 12)
	if n, err := rand.Reader.Read(blob); err != nil || n != len(blob) {
		return nil
	}
	return new(big.Int).SetBytes(blob)
}

func setUsage(template *x509.Certificate) error {
	usage := x509.KeyUsageDigitalSignature
	var extended x509.ExtKeyUsage
	switch strings.ToLower(argKeyUsage) {
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

func makeRequest(key *p11token.Key) (string, error) {
	var template x509.CertificateRequest
	template.Subject = subjName()
	template.DNSNames = splitAndTrim(argDnsNames)
	template.EmailAddresses = splitAndTrim(argEmailNames)
	template.SignatureAlgorithm = key.X509SignatureAlgorithm()
	csr, err := x509.CreateCertificateRequest(nil, &template, key)
	if err != nil {
		return "", err
	}
	block := &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}
	return string(pem.EncodeToMemory(block)), nil
}

func makeCertificate(key *p11token.Key) (string, error) {
	var template x509.Certificate
	template.SerialNumber = makeSerial()
	if template.SerialNumber == nil {
		return "", errors.New("Failed to generate a serial number")
	}
	template.Subject = subjName()
	template.DNSNames = splitAndTrim(argDnsNames)
	template.EmailAddresses = splitAndTrim(argEmailNames)
	template.SignatureAlgorithm = key.X509SignatureAlgorithm()
	template.NotBefore = time.Now().Add(time.Hour * -24)
	template.NotAfter = time.Now().Add(time.Hour * 24 * time.Duration(argExpireDays))
	template.SubjectKeyId = key.GetId()
	template.IsCA = true
	template.BasicConstraintsValid = true
	if err := setUsage(&template); err != nil {
		return "", err
	}
	template.Issuer = template.Subject
	cert, err := x509.CreateCertificate(nil, &template, &template, key.Public(), key)
	if err != nil {
		return "", err
	}
	block := &pem.Block{Type: "CERTIFICATE", Bytes: cert}
	return string(pem.EncodeToMemory(block)), nil
}

func x509Cmd(cmd *cobra.Command, args []string) error {
	if argCommonName == "" {
		return errors.New("--commonName is required")
	}
	key, err := selectOrGenerate()
	if err != nil {
		return err
	}
	var result string
	if cmd == ReqCmd {
		result, err = makeRequest(key)
	} else {
		result, err = makeCertificate(key)
	}
	if err != nil {
		return err
	}
	os.Stdout.WriteString(result)
	fmt.Println("CKA_ID:", formatKeyId(key.GetId()))
	return nil
}
