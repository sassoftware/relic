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
	"archive/zip"
	"errors"
	"io/ioutil"
	"os"

	"gerrit-pdt.unx.sas.com/tools/relic.git/cmdline/shared"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/atomicfile"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/certloader"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/pkcs7"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/signjar"
	"github.com/spf13/cobra"
)

var SignJarCmd = &cobra.Command{
	Use:   "sign-jar",
	Short: "Sign a Jar JAR using a X509 key in a token",
	RunE:  signJarCmd,
}

var SignJarManifestCmd = &cobra.Command{
	Use:   "sign-jar-manifest",
	Short: "Sign a Jar JAR manifest using a X509 key in a token",
	RunE:  signJarManifestCmd,
}

var (
	argSignFileOutput string
	argKeyAlias       string
)

func init() {
	shared.RootCmd.AddCommand(SignJarCmd)
	shared.AddDigestFlag(SignJarCmd)
	SignJarCmd.Flags().StringVarP(&argKeyName, "key", "k", "", "Name of key section in config file to use")
	SignJarCmd.Flags().StringVarP(&argFile, "file", "f", "", "Input JAR file to sign")
	SignJarCmd.Flags().StringVarP(&argOutput, "output", "o", "", "Output file for JAR. Defaults to same as input.")
	SignJarCmd.Flags().StringVar(&argKeyAlias, "key-alias", "RELIC", "Alias to use for the signed manifest")

	shared.RootCmd.AddCommand(SignJarManifestCmd)
	shared.AddDigestFlag(SignJarManifestCmd)
	SignJarManifestCmd.Flags().StringVarP(&argKeyName, "key", "k", "", "Name of key section in config file to use")
	SignJarManifestCmd.Flags().StringVarP(&argFile, "file", "f", "", "Input manifest file to sign")
	SignJarManifestCmd.Flags().StringVarP(&argOutput, "output", "o", "", "Output file for signature (.RSA or .EC)")
	SignJarManifestCmd.Flags().StringVar(&argSignFileOutput, "out-sf", "", "Write .SF file")
}

func signJarCmd(cmd *cobra.Command, args []string) (err error) {
	if argFile == "" {
		return errors.New("--key and --file are required")
	} else if argFile == "-" || argOutput == "-" {
		return errors.New("--file and --output must be paths, not -")
	}
	hash, err := shared.GetDigest()
	if err != nil {
		return err
	}
	inz, err := zip.OpenReader(argFile)
	if err != nil {
		return err
	}
	manifest, err := signjar.DigestJar(&inz.Reader, hash)
	if err != nil {
		return err
	}

	key, err := openKey(argKeyName)
	if err != nil {
		return err
	}
	certblob, err := ioutil.ReadFile(key.Certificate)
	if err != nil {
		return err
	}
	certs, err := certloader.ParseCertificates(certblob)
	if err != nil {
		return err
	}
	sigfile, err := signjar.DigestManifest(manifest, hash)
	if err != nil {
		return err
	}
	d := hash.New()
	d.Write(sigfile)
	pkcs, err := pkcs7.SignDetached(d.Sum(nil), key, certs, hash)
	if err != nil {
		return err
	}

	if argOutput == "" {
		argOutput = argFile
	}
	w, err := atomicfile.WriteAny(argOutput)
	if err != nil {
		return err
	}
	defer w.Close()
	if err := signjar.UpdateJar(w, &inz.Reader, argKeyAlias, key.Public(), manifest, sigfile, pkcs); err != nil {
		return err
	}
	inz.Close()
	return w.Commit()
}

func signJarManifestCmd(cmd *cobra.Command, args []string) (err error) {
	if argFile == "" || argOutput == "" {
		return errors.New("--key, --file and --output are required")
	}
	hash, err := shared.GetDigest()
	if err != nil {
		return err
	}
	var manifest []byte
	if argFile == "-" {
		manifest, err = ioutil.ReadAll(os.Stdin)
	} else {
		manifest, err = ioutil.ReadFile(argFile)
	}
	if err != nil {
		return err
	}

	key, err := openKey(argKeyName)
	if err != nil {
		return err
	}
	certblob, err := ioutil.ReadFile(key.Certificate)
	if err != nil {
		return err
	}
	certs, err := certloader.ParseCertificates(certblob)
	if err != nil {
		return err
	}
	sigfile, err := signjar.DigestManifest(manifest, hash)
	if err != nil {
		return err
	}
	var pkcs []byte
	if argSignFileOutput != "" {
		d := hash.New()
		d.Write(sigfile)
		pkcs, err = pkcs7.SignDetached(d.Sum(nil), key, certs, hash)
		if err != nil {
			return err
		}
		if err := ioutil.WriteFile(argSignFileOutput, sigfile, 0666); err != nil {
			return err
		}
	} else {
		// only useful for server so there's a single blob to send back
		pkcs, err = pkcs7.SignData(sigfile, key, certs, hash)
		if err != nil {
			return err
		}
	}

	if argOutput == "-" {
		_, err = os.Stdout.Write(pkcs)
	} else {
		err = ioutil.WriteFile(argOutput, pkcs, 0666)
	}
	return err
}
