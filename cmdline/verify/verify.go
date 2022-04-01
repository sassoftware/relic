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

package verify

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/sassoftware/relic/v7/cmdline/shared"
	"github.com/sassoftware/relic/v7/lib/certloader"
	"github.com/sassoftware/relic/v7/lib/magic"
	"github.com/sassoftware/relic/v7/lib/pgptools"
	"github.com/sassoftware/relic/v7/lib/x509tools"
	"github.com/sassoftware/relic/v7/signers"
)

var VerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify a signed package or executable",
	RunE:  verifyCmd,
}

var (
	argNoIntegrityCheck bool
	argNoChain          bool
	argAlsoSystem       bool
	argShowCerts        bool
	argContent          string
	argTrustedCerts     []string
)

func init() {
	shared.RootCmd.AddCommand(VerifyCmd)
	VerifyCmd.Flags().BoolVar(&argNoIntegrityCheck, "no-integrity-check", false, "Bypass the integrity check of the file contents and only inspect the signature itself")
	VerifyCmd.Flags().BoolVar(&argNoChain, "no-trust-chain", false, "Do not test whether the signing certificate is trusted")
	VerifyCmd.Flags().BoolVar(&argAlsoSystem, "system-store", false, "When --cert is used, append rather than replace the system trust store")
	VerifyCmd.Flags().BoolVar(&argShowCerts, "show-certs", false, "Dump certificate chain from signature")
	VerifyCmd.Flags().StringVar(&argContent, "content", "", "Specify file containing contents for detached signatures")
	VerifyCmd.Flags().StringArrayVar(&argTrustedCerts, "cert", nil, "Add a trusted root certificate (PEM, DER, PKCS#7, or PGP)")
}

func verifyCmd(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return errors.New("Expected 1 or more files")
	}
	opts, err := loadCerts()
	if err != nil {
		return err
	}
	rc := 0
	for _, path := range args {
		if err := verifyOne(path, opts); err != nil {
			fmt.Printf("%s ERROR: %s\n", path, err)
			rc = 1
		}
	}
	if rc != 0 {
		fmt.Fprintln(os.Stderr, "ERROR: 1 or more files did not validate")
	}
	os.Exit(rc)
	return nil
}

func verifyOne(path string, opts signers.VerifyOpts) error {
	f, err := shared.OpenFile(path)
	if err != nil {
		return err
	}
	defer f.Close()
	fileType, compression := magic.DetectCompressed(f)
	opts.FileName = path
	opts.Compression = compression
	if _, err := f.Seek(0, 0); err != nil {
		return err
	}
	mod := signers.ByMagic(fileType)
	if mod == nil {
		mod = signers.ByFileName(path)
	}
	if mod == nil {
		return errors.New("unknown filetype")
	}
	var sigs []*signers.Signature
	if mod.VerifyStream != nil {
		r, err2 := magic.Decompress(f, opts.Compression)
		if err2 != nil {
			return err
		}
		sigs, err = mod.VerifyStream(r, opts)
	} else {
		if opts.Compression != magic.CompressedNone {
			return errors.New("cannot verify compressed file")
		}
		sigs, err = mod.Verify(f, opts)
	}
	if err != nil {
		if _, ok := err.(pgptools.ErrNoKey); ok {
			return fmt.Errorf("%w; use --cert to specify known keys", err)
		}
		return err
	}
	sawCerts := make(map[string]bool)
	for _, sig := range sigs {
		var si, pkg, ts string
		if sig.SigInfo != "" {
			si = " " + sig.SigInfo + ":"
		}
		if sig.Package != "" {
			pkg = sig.Package + " "
		}
		if sig.X509Signature != nil && argShowCerts {
			showCert(sig.X509Signature.Certificate.Raw, sawCerts)
			for _, cert := range sig.X509Signature.Intermediates {
				showCert(cert.Raw, sawCerts)
			}
		}
		if sig.X509Signature != nil && !opts.NoChain {
			if err := sig.X509Signature.VerifyChain(opts.TrustedPool, nil, x509.ExtKeyUsageAny); err != nil {
				if e := new(x509.UnknownAuthorityError); errors.As(err, e) {
					fmt.Printf("While validating certificate:\n Subject: %s\n Issuer:  %s\n Serial:  %X\n", x509tools.FormatSubject(e.Cert), x509tools.FormatIssuer(e.Cert), e.Cert.SerialNumber)
				}
				return err
			}
		}
		if sig.X509Signature != nil && sig.X509Signature.CounterSignature != nil {
			fmt.Printf("%s: OK -%s %s%s\n", path, si, pkg, sig.SignerName())
			fmt.Printf("%s(timestamp): OK - `%s` [%s]\n", path, x509tools.FormatSubject(sig.X509Signature.CounterSignature.Certificate), sig.X509Signature.CounterSignature.SigningTime)
		} else {
			if !sig.CreationTime.IsZero() {
				ts = fmt.Sprintf(" [%s]", sig.CreationTime)
			}
			fmt.Printf("%s: OK -%s %s%s%s\n", path, si, pkg, sig.SignerName(), ts)
		}
	}
	return nil
}

func loadCerts() (signers.VerifyOpts, error) {
	opts := signers.VerifyOpts{
		NoChain:   argNoChain,
		NoDigests: argNoIntegrityCheck,
		Content:   argContent,
	}
	trusted, err := certloader.LoadAnyCerts(argTrustedCerts)
	if err != nil {
		return opts, err
	}
	opts.TrustedX509 = trusted.X509Certs
	opts.TrustedPgp = trusted.PGPCerts
	if len(opts.TrustedX509) > 0 {
		if argAlsoSystem {
			var err error
			opts.TrustedPool, err = x509.SystemCertPool()
			if err != nil {
				return opts, err
			}
		} else {
			opts.TrustedPool = x509.NewCertPool()
		}
		for _, cert := range opts.TrustedX509 {
			opts.TrustedPool.AddCert(cert)
		}
	}
	return opts, nil
}

func showCert(blob []byte, seen map[string]bool) {
	if seen[string(blob)] {
		return
	}
	seen[string(blob)] = true
	_ = pem.Encode(os.Stdout, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: blob,
	})
}
