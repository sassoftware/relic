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

package servecmd

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/sassoftware/relic/cmdline/shared"
	"github.com/sassoftware/relic/lib/certloader"
	"github.com/sassoftware/relic/lib/x509tools"
	"github.com/spf13/cobra"
)

var SetupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Generate private key and certificate request for server",
	RunE:  setupCmd,
}

var (
	argRsaBits   uint
	argEcdsaBits uint
	argSelfSign  bool
)

func init() {
	SetupCmd.Flags().UintVar(&argRsaBits, "generate-rsa", 0, "Generate a RSA key of the specified bit size, if needed")
	SetupCmd.Flags().UintVar(&argEcdsaBits, "generate-ecdsa", 0, "Generate an ECDSA key of the specified curve size, if needed")
	SetupCmd.Flags().BoolVar(&argSelfSign, "self-sign", false, "Make and store a self-signed certificate instead of a request")
	x509tools.AddRequestFlags(SetupCmd)
	ServeCmd.AddCommand(SetupCmd)
}

func readKey(path string) (crypto.PrivateKey, error) {
	pemData, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return certloader.ParseAnyPrivateKey(pemData, nil)
}

func selectOrGenerate(path string) (crypto.PrivateKey, error) {
	key, err := readKey(path)
	if err == nil {
		fmt.Fprintf(os.Stderr, "Using existing private key at %s\n", path)
		return key, nil
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("reading private key: %w", err)
	}
	var block *pem.Block
	if argRsaBits != 0 {
		rsaKey, err := rsa.GenerateKey(rand.Reader, int(argRsaBits))
		if err != nil {
			return nil, err
		}
		key = rsaKey
		keyBytes := x509.MarshalPKCS1PrivateKey(rsaKey)
		block = &pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes}
	} else if argEcdsaBits != 0 {
		curve, err := x509tools.CurveByBits(argEcdsaBits)
		if err != nil {
			return nil, err
		}
		ecKey, err := ecdsa.GenerateKey(curve.Curve, rand.Reader)
		if err != nil {
			return nil, err
		}
		key = ecKey
		keyBytes, err := x509.MarshalECPrivateKey(ecKey)
		if err != nil {
			return nil, err
		}
		block = &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}
	} else {
		return nil, errors.New("No matching key exists, specify --generate-rsa or --generate-ecdsa to generate one")
	}
	pemData := pem.EncodeToMemory(block)
	if err := ioutil.WriteFile(path, pemData, 0600); err != nil {
		return nil, fmt.Errorf("writing new private key: %w", err)
	}
	fmt.Fprintf(os.Stderr, "Wrote new private key to %s\n", path)
	return key, nil
}

func setupCmd(cmd *cobra.Command, args []string) error {
	if err := shared.InitConfig(); err != nil {
		return err
	}
	if shared.CurrentConfig.Server == nil {
		return errors.New("Missing server section in configuration file")
	}
	if shared.CurrentConfig.Server.KeyFile == "" {
		return errors.New("Missing keyfile option in server configuration file")
	}
	if argSelfSign && shared.CurrentConfig.Server.KeyFile == "" {
		return errors.New("Missing certfile option in server configuration file")
	}
	if x509tools.ArgCommonName == "" {
		return errors.New("--commonName is required")
	}
	if x509tools.ArgDNSNames == "" && x509tools.ArgEmailNames == "" {
		fmt.Fprintf(os.Stderr, "Subject alternate names is empty; appending %s\n", x509tools.ArgCommonName)
		x509tools.ArgDNSNames = x509tools.ArgCommonName
	}
	key, err := selectOrGenerate(shared.CurrentConfig.Server.KeyFile)
	if err != nil {
		return err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		panic("expected a signer")
	}
	if argSelfSign {
		x509tools.ArgExpireDays = 36525
		x509tools.ArgCertAuthority = true
		cert, err := x509tools.MakeCertificate(rand.Reader, signer)
		if err != nil {
			return err
		}
		err = ioutil.WriteFile(shared.CurrentConfig.Server.CertFile, []byte(cert), 0600)
		if err != nil {
			return err
		}
	} else {
		req, err := x509tools.MakeRequest(rand.Reader, signer)
		if err != nil {
			return err
		}
		os.Stdout.WriteString(req)
	}
	return nil
}
