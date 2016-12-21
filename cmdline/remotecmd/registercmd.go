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

package remotecmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"path"
	"time"

	"gerrit-pdt.unx.sas.com/tools/relic.git/cmdline/shared"
	"gerrit-pdt.unx.sas.com/tools/relic.git/config"
	"gopkg.in/yaml.v2"

	"github.com/spf13/cobra"
)

var RegisterCmd = &cobra.Command{
	Use:   "register",
	Short: "Generate a certificate for communicating with a server",
	RunE:  registerCmd,
}

var (
	argRemoteUrl string
	argCaCert    string
)

func init() {
	RemoteCmd.AddCommand(RegisterCmd)
	RegisterCmd.Flags().StringVarP(&argRemoteUrl, "url", "u", "", "URL of remote server to register to")
	RegisterCmd.Flags().StringVarP(&argCaCert, "ca-cert", "C", "", "Path to CA certificate file (will be copied)")
}

func registerCmd(cmd *cobra.Command, args []string) error {
	if argRemoteUrl == "" || argCaCert == "" {
		return errors.New("--url and --ca-cert are required")
	}
	if shared.ArgConfig == "" {
		shared.ArgConfig = config.DefaultConfig()
		if shared.ArgConfig == "" {
			return errors.New("Unable to determine default config location")
		}
	}
	if fileExists(shared.ArgConfig) {
		return fmt.Errorf("Config file %s already exists", shared.ArgConfig)
	}
	defaultDir := config.DefaultDir()
	if defaultDir == "" {
		return errors.New("Unable to determine default config location")
	}
	keyPath := path.Join(defaultDir, "client.pem")
	if fileExists(keyPath) {
		return fmt.Errorf("Key file %s already exists", keyPath)
	}
	if err := writeKeyPair(keyPath); err != nil {
		return err
	}
	cacert, err := ioutil.ReadFile(argCaCert)
	if err != nil {
		return fmt.Errorf("Error reading cacert: %s", err)
	}
	capath := path.Join(defaultDir, "cacert.pem")
	if err = writeConfig(shared.ArgConfig, argRemoteUrl, keyPath, capath); err != nil {
		return err
	}
	if err = ioutil.WriteFile(capath, cacert, 0644); err != nil {
		return err
	}
	return nil
}

func fileExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

func writeConfig(cfgPath, url, keyPath, caPath string) error {
	newConfig := &config.Config{Remote: &config.RemoteConfig{}}
	newConfig.Remote.Url = url
	newConfig.Remote.CertFile = keyPath
	newConfig.Remote.KeyFile = keyPath
	newConfig.Remote.CaCert = caPath
	cfgblob, err := yaml.Marshal(newConfig)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(path.Dir(cfgPath), 0755); err != nil {
		return err
	}
	return ioutil.WriteFile(cfgPath, cfgblob, 0600)
}

func writeKeyPair(keyPath string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	cert, fingerprint, err := selfSign(key)
	if err != nil {
		return err
	}
	pemdata, err := serializeKey(key)
	if err != nil {
		return err
	}
	pemdata = append(pemdata, cert...)
	if err = os.MkdirAll(path.Dir(keyPath), 0755); err != nil {
		return err
	}
	if err = ioutil.WriteFile(keyPath, pemdata, 0600); err != nil {
		return err
	}
	fmt.Println("New key fingerprint:", fingerprint)
	return nil
}

func selfSign(key *ecdsa.PrivateKey) ([]byte, string, error) {
	blob := make([]byte, 12)
	if n, err := rand.Reader.Read(blob); err != nil || n != len(blob) {
		return nil, "", errors.New("failed to make serial number")
	}
	hostname, _ := os.Hostname()
	var template x509.Certificate
	template.SerialNumber = new(big.Int).SetBytes(blob)
	template.Subject.CommonName = fmt.Sprintf("self-signed cert for %s", hostname)
	template.Issuer = template.Subject
	template.SignatureAlgorithm = x509.ECDSAWithSHA256
	template.NotBefore = time.Now().Add(time.Hour * -24)
	template.NotAfter = time.Now().Add(time.Hour * 24 * 36525)
	certblob, err := x509.CreateCertificate(rand.Reader, &template, &template, key.Public(), key)
	if err != nil {
		return nil, "", err
	}
	cert, err := x509.ParseCertificate(certblob)
	if err != nil {
		return nil, "", err
	}
	digest := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	encoded := hex.EncodeToString(digest[:])
	block := &pem.Block{Type: "CERTIFICATE", Bytes: certblob}
	return pem.EncodeToMemory(block), encoded, nil
}

func serializeKey(key *ecdsa.PrivateKey) ([]byte, error) {
	blob, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	block := &pem.Block{Type: "EC PRIVATE KEY", Bytes: blob}
	return pem.EncodeToMemory(block), nil
}
