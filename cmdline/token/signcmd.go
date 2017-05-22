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
	"bytes"
	"crypto"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gerrit-pdt.unx.sas.com/tools/relic.git/cmdline/shared"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/atomicfile"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/audit"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/certloader"
	"gerrit-pdt.unx.sas.com/tools/relic.git/signers"
	"gerrit-pdt.unx.sas.com/tools/relic.git/signers/pkcs"
	"gerrit-pdt.unx.sas.com/tools/relic.git/signers/sigerrors"
	"github.com/spf13/cobra"
)

var SignCmd = &cobra.Command{
	Use:   "sign",
	Short: "Sign a package using a token",
	RunE:  signCmd,
}

var (
	argSigType string
	argOutput  string
	argServer  bool
)

func init() {
	shared.RootCmd.AddCommand(SignCmd)
	SignCmd.Flags().StringVarP(&argKeyName, "key", "k", "", "Name of key to use")
	SignCmd.Flags().StringVarP(&argFile, "file", "f", "", "Input file to sign")
	SignCmd.Flags().StringVarP(&argOutput, "output", "o", "", "Output file")
	SignCmd.Flags().StringVarP(&argSigType, "sig-type", "T", "", "Specify signature type (default: auto-detect)")
	SignCmd.Flags().BoolVar(&argServer, "server", false, "")
	SignCmd.Flags().MarkHidden("server")
	shared.AddDigestFlag(SignCmd)
	shared.AddLateHook(func() {
		signers.MergeFlags(SignCmd.Flags())
	})
}

func signCmd(cmd *cobra.Command, args []string) error {
	if argFile == "" || argKeyName == "" {
		return errors.New("--file and --key are required")
	}
	if argOutput == "" {
		argOutput = argFile
	}
	mod, err := signers.ByFile(argFile, argSigType)
	if err != nil {
		return shared.Fail(err)
	}
	if mod.Sign == nil {
		return shared.Fail(errors.New("can't sign this type of file"))
	}
	flags, err := mod.GetFlags(cmd.Flags())
	if err != nil {
		return err
	}
	hash, err := shared.GetDigest()
	if err != nil {
		return err
	}
	cert, ai, err := openCert(mod, hash)
	if err != nil {
		return shared.Fail(err)
	}
	if ai.Attributes["client.filename"] == nil {
		ai.Attributes["client.filename"] = filepath.Base(argFile)
	}
	opts := signers.SignOpts{
		Path:         argFile,
		Hash:         hash,
		Time:         time.Now().UTC(),
		Flags:        flags,
		FlagOverride: make(map[string]string),
		Audit:        ai,
	}
	if err := setTimestamper(&opts); err != nil {
		return shared.Fail(err)
	}
	infile, err := openForPatching()
	if err != nil {
		return shared.Fail(err)
	}
	defer infile.Close()
	if argServer {
		// sign an already-transformed stream and output a sig blob
		blob, err := mod.Sign(infile, cert, opts)
		if err != nil {
			return shared.Fail(err)
		}
		if err := atomicfile.WriteFile(argOutput, blob); err != nil {
			return shared.Fail(err)
		}
	} else {
		// transform the input, sign the stream, and apply the result
		transform, err := mod.GetTransform(infile, opts)
		if err != nil {
			return shared.Fail(err)
		}
		stream, err := transform.GetReader()
		if err != nil {
			return shared.Fail(err)
		}
		blob, err := mod.Sign(stream, cert, opts)
		if err != nil {
			return shared.Fail(err)
		}
		mimeType := opts.Audit.GetMimeType()
		if err := transform.Apply(argOutput, mimeType, bytes.NewReader(blob)); err != nil {
			return shared.Fail(err)
		}
	}
	if err := PublishAudit(opts.Audit); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Signed", argFile)
	return nil
}

func openCert(mod *signers.Signer, hash crypto.Hash) (*certloader.Certificate, *audit.Info, error) {
	key, err := openKey(argKeyName)
	if err != nil {
		return nil, nil, err
	}
	var x509cert, pgpcert string
	if mod.CertTypes&signers.CertTypeX509 != 0 {
		if key.Config().X509Certificate == "" {
			return nil, nil, sigerrors.ErrNoCertificate{"x509"}
		}
		x509cert = key.Config().X509Certificate
	}
	if mod.CertTypes&signers.CertTypePgp != 0 {
		if key.Config().PgpCertificate == "" {
			return nil, nil, sigerrors.ErrNoCertificate{"pgp"}
		}
		pgpcert = key.Config().PgpCertificate
	}
	cert, err := certloader.LoadTokenCertificates(key, x509cert, pgpcert)
	if err != nil {
		return nil, nil, err
	}
	cert.KeyName = key.Config().Name()
	ai := audit.New(key.Config().Name(), mod.Name, hash)
	if cert.Leaf != nil {
		ai.SetX509Cert(cert.Leaf)
	}
	if cert.PgpKey != nil {
		ai.SetPgpCert(cert.PgpKey)
	}
	if keyConf, err := shared.CurrentConfig.GetKey(argKeyName); err == nil && keyConf.Timestamp {
		cert.Timestamper = pkcs.Timestamper{Config: shared.CurrentConfig.Timestamp}
	}
	return cert, ai, nil
}

func setTimestamper(opts *signers.SignOpts) error {
	keyConf, err := shared.CurrentConfig.GetKey(argKeyName)
	if err != nil {
		return err
	}
	if keyConf.Timestamp {
		tconf, err := shared.CurrentConfig.GetTimestampConfig()
		if err != nil {
			return err
		}
		opts.TimestampConfig = tconf
	}
	opts.Audit.SetTimestamp(opts.Time)
	return nil
}

func openForPatching() (*os.File, error) {
	if argFile == "-" && argServer {
		return os.Stdin, nil
	} else if argServer {
		return os.Open(argFile)
	} else {
		return os.OpenFile(argFile, os.O_RDWR, 0)
	}
}
