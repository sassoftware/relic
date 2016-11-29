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

package cmdline

import (
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"gerrit-pdt.unx.sas.com/tools/relic.git/p11token"
	"github.com/sassoftware/go-rpmutils"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/openpgp/packet"
)

var SignRpmCmd = &cobra.Command{
	Use:   "sign-rpm",
	Short: "Sign a RPM using a PGP key in a token",
	RunE:  signRpmCmd,
}

func init() {
	RootCmd.AddCommand(SignRpmCmd)
	SignRpmCmd.Flags().StringVarP(&argKeyName, "key", "k", "", "name of key section in config file to use")
	SignRpmCmd.Flags().StringVarP(&argFile, "file", "f", "", "Input RPM file to sign")
	SignRpmCmd.Flags().StringVarP(&argOutput, "output", "o", "", "Output RPM file")
	SignRpmCmd.Flags().BoolVarP(&argJson, "json-output", "j", false, "Print signature tags instead of writing a RPM")
}

func keyFromToken(key *p11token.Key, keyName string) (*packet.PrivateKey, error) {
	keyConf, err := currentConfig.GetKey(keyName)
	if err != nil {
		return nil, err
	}
	if keyConf.Certificate == "" {
		return nil, errors.New("'certificate' setting in key configuration must point to a PGP public key file")
	}
	entity, err := readEntity(keyConf.Certificate)
	if err != nil {
		return nil, err
	}
	priv := &packet.PrivateKey{
		PublicKey:  *entity.PrimaryKey,
		Encrypted:  false,
		PrivateKey: key,
	}
	return priv, checkPublicKey(key, &priv.PublicKey)
}

func checkPublicKey(token *p11token.Key, pub *packet.PublicKey) error {
	// TODO
	return nil
}

type jsonInfo struct {
	Fingerprint string    `json:"fingerprint"`
	HeaderSig   []byte    `json:"header_sig"`
	Md5         string    `json:"md5"`
	Nevra       string    `json:"nevra"`
	PayloadSig  []byte    `json:"payload_sig"`
	Sha1        string    `json:"sha1"`
	Timestamp   time.Time `json:"timestamp"`
}

func dumpInfo(header *rpmutils.RpmHeader, key *packet.PrivateKey, timestamp time.Time) {
	var info jsonInfo
	info.HeaderSig, _ = header.GetBytes(rpmutils.SIG_RSA)
	info.PayloadSig, _ = header.GetBytes(rpmutils.SIG_PGP)
	info.Fingerprint = fmt.Sprintf("%X", key.PublicKey.Fingerprint)
	nevra, _ := header.GetNEVRA()
	info.Nevra = nevra.String()
	md5, _ := header.GetBytes(rpmutils.SIG_MD5)
	info.Md5 = fmt.Sprintf("%x", md5)
	info.Sha1, _ = header.GetString(rpmutils.SIG_SHA1)
	info.Timestamp = timestamp

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(&info)
	fmt.Println()
}

func logInfo(header *rpmutils.RpmHeader, key *packet.PrivateKey, timestamp time.Time) {
	nevra, _ := header.GetNEVRA()
	md5, _ := header.GetBytes(rpmutils.SIG_MD5)
	sha1, _ := header.GetString(rpmutils.SIG_SHA1)
	fmt.Fprintf(os.Stderr, "Signed %s using %s(%X) md5=%X sha1=%s\n", nevra, argKeyName, key.PublicKey.Fingerprint, md5, sha1)
}

func signRpmCmd(cmd *cobra.Command, args []string) (err error) {
	if argFile == "" {
		return errors.New("--key and --file are required")
	}
	var rpmfile *os.File
	if argFile == "-" {
		rpmfile = os.Stdin
	} else {
		rpmfile, err = os.Open(argFile)
		if err != nil {
			return
		}
	}
	token, key, err := openKey(argKeyName)
	if err != nil {
		return err
	}
	defer token.Close()
	signer, err := keyFromToken(key, argKeyName)
	if err != nil {
		return err
	}
	opts := &rpmutils.SignatureOptions{
		Hash:         crypto.SHA256,
		CreationTime: time.Now().UTC().Round(time.Second),
	}
	if argJson {
		header, err := rpmutils.SignRpmStream(rpmfile, signer, opts)
		if err != nil {
			return err
		}
		dumpInfo(header, signer, opts.CreationTime)
	} else {
		if argOutput == "" {
			argOutput = argFile
		}
		header, err := rpmutils.SignRpmFile(rpmfile, argOutput, signer, opts)
		if err != nil {
			return err
		}
		logInfo(header, signer, opts.CreationTime)
	}
	return nil
}
