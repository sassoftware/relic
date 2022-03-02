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
	"io"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/sassoftware/relic/cmdline/shared"
	"github.com/sassoftware/relic/config"
	"github.com/sassoftware/relic/lib/certloader"
	"gopkg.in/yaml.v3"

	"github.com/spf13/cobra"
)

var RegisterCmd = &cobra.Command{
	Use:   "register",
	Short: "Generate a certificate for communicating with a server",
	RunE:  registerCmd,
}

var (
	argRemoteURL string
	argCaCert    string
	argDirectory bool
	argForce     bool
	argEmbed     bool
)

func init() {
	RemoteCmd.AddCommand(RegisterCmd)
	RegisterCmd.Flags().StringVarP(&argRemoteURL, "url", "u", "", "URL of remote server to register to")
	RegisterCmd.Flags().StringVarP(&argCaCert, "ca-cert", "C", "", "Path to CA certificate file (will be copied)")
	RegisterCmd.Flags().BoolVarP(&argDirectory, "directory", "D", false, "Remote URL is a cluster directory")
	RegisterCmd.Flags().BoolVarP(&argForce, "force", "f", false, "Overwrite existing configuration file")
	RegisterCmd.Flags().BoolVarP(&argEmbed, "embed", "E", false, "Embed certificate in config file")
}

func registerCmd(cmd *cobra.Command, args []string) error {
	if argRemoteURL == "" {
		return errors.New("--url and --ca-cert are required")
	}
	if shared.ArgConfig == "" {
		shared.ArgConfig = config.DefaultConfig()
		if shared.ArgConfig == "" {
			return errors.New("Unable to determine default config location")
		}
	}
	if fileExists(shared.ArgConfig) && !argForce {
		fmt.Fprintf(os.Stderr, "Config file %s already exists\n", shared.ArgConfig)
		return nil
	}
	var cacert []byte
	var err error
	if argCaCert != "" {
		cacert, err = ioutil.ReadFile(argCaCert)
		if err != nil {
			return shared.Fail(fmt.Errorf("reading cacert: %w", err))
		}
	}
	var certPath, keyPath, capath string
	if argEmbed {
		// embed generated PEM into config
		certPEM, keyPEM, fingerprint, err := genKeyPair()
		if err != nil {
			return shared.Fail(err)
		}
		fmt.Fprintln(os.Stderr, "New key fingerprint:", fingerprint)
		certPath = string(certPEM)
		keyPath = string(keyPEM)
		capath = string(cacert)
	} else {
		// write generated PEM to file
		defaultDir := filepath.Dir(shared.ArgConfig)
		keyPath = filepath.Join(defaultDir, "client.pem")
		certPath = keyPath
		if fileExists(keyPath) {
			if !argForce {
				return shared.Fail(fmt.Errorf("Key file %s already exists", keyPath))
			}
			if err := readKeyPair(keyPath); err != nil {
				return shared.Fail(err)
			}
		} else {
			if err := writeKeyPair(keyPath); err != nil {
				return shared.Fail(err)
			}
		}
		if len(cacert) != 0 {
			capath = filepath.Join(defaultDir, "cacert.pem")
			if err := ioutil.WriteFile(capath, cacert, 0644); err != nil {
				return shared.Fail(err)
			}
		}
	}
	if err := writeConfig(shared.ArgConfig, argRemoteURL, certPath, keyPath, capath); err != nil {
		return shared.Fail(err)
	}
	return nil
}

func fileExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

func writeConfig(cfgPath, url, certPath, keyPath, caPath string) error {
	newConfig := &config.Config{Remote: &config.RemoteConfig{}}
	if argDirectory {
		newConfig.Remote.DirectoryURL = url
	} else {
		newConfig.Remote.URL = url
	}
	newConfig.Remote.CertFile = certPath
	newConfig.Remote.KeyFile = keyPath
	newConfig.Remote.CaCert = caPath
	cfgblob, err := yaml.Marshal(newConfig)
	if err != nil {
		return err
	}
	if cfgPath == "-" {
		os.Stdout.Write(cfgblob)
		return nil
	}
	if err = os.MkdirAll(filepath.Dir(cfgPath), 0755); err != nil {
		return err
	}
	return ioutil.WriteFile(cfgPath, cfgblob, 0600)
}

func genKeyPair() (certPEM, keyPEM []byte, fingerprint string, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return
	}
	certPEM, fingerprint, err = selfSign(key)
	if err != nil {
		return
	}
	keyPEM, err = serializeKey(key)
	return
}

func writeKeyPair(keyPath string) error {
	certPEM, keyPEM, fingerprint, err := genKeyPair()
	if err != nil {
		return err
	}
	pemdata := append(keyPEM, certPEM...)
	if err = os.MkdirAll(filepath.Dir(keyPath), 0755); err != nil {
		return err
	}
	if err = ioutil.WriteFile(keyPath, pemdata, 0600); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "New key fingerprint:", fingerprint)
	return nil
}

func readKeyPair(keyPath string) error {
	cert, err := certloader.LoadX509KeyPair(keyPath, keyPath)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(cert.Leaf.RawSubjectPublicKeyInfo)
	encoded := hex.EncodeToString(digest[:])
	fmt.Println("Existing key fingerprint:", encoded)
	return nil
}

func selfSign(key *ecdsa.PrivateKey) ([]byte, string, error) {
	blob := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, blob); err != nil {
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
