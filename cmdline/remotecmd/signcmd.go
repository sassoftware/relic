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
	"crypto"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/url"
	"os"
	"path"

	"gerrit-pdt.unx.sas.com/tools/relic.git/cmdline/shared"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/authenticode"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/binpatch"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/magic"
	"github.com/spf13/cobra"
)

var SignCmd = &cobra.Command{
	Use:   "sign",
	Short: "Sign a package using a remote signing server",
	RunE:  signCmd,
}

var (
	argKeyAlias      string
	argRole          string
	argPageHashes    bool
	argNoMsiExtended bool
)

func init() {
	RemoteCmd.AddCommand(SignCmd)
	SignCmd.Flags().StringVarP(&argKeyName, "key", "k", "", "Name of key on remote server to use")
	SignCmd.Flags().StringVarP(&argFile, "file", "f", "", "Input file to sign")
	SignCmd.Flags().StringVarP(&argOutput, "output", "o", "", "Output file. Defaults to same as --file.")
	SignCmd.Flags().StringVar(&argKeyAlias, "key-alias", "RELIC", "Alias to use for signed manifests (JAR only)")
	SignCmd.Flags().StringVar(&argRole, "role", "", "Debian package signing role (DEB only)")
	SignCmd.Flags().BoolVar(&argPageHashes, "page-hashes", false, "Add page hashes (PE only)")
	SignCmd.Flags().BoolVar(&argNoMsiExtended, "no-extended-sig", false, "Don't emit a MsiDigitalSignatureEx digest (MSI only)")
	shared.AddDigestFlag(SignCmd)
}

func signCmd(cmd *cobra.Command, args []string) (err error) {
	if argFile == "" || argKeyName == "" {
		return errors.New("--file and --key are required")
	}
	if argOutput == "" {
		argOutput = argFile
	}
	// check if an external tool will be used. if so we want to upload the file
	// as-is, even for filetypes we'd normally transform first.
	info, err := getKeyInfo(argKeyName)
	if err != nil {
		return shared.Fail(fmt.Errorf("failed to get info about key %s: %s", argKeyName, err))
	}
	var sigType string
	var fileType magic.FileType
	if !info.ExternalTool {
		if f, err := os.Open(argFile); err != nil {
			return shared.Fail(err)
		} else {
			fileType = magic.Detect(f)
			f.Close()
		}
		switch fileType {
		case magic.FileTypeJAR:
			return signJar()
		case magic.FileTypeMSI:
			return signMsi()
		case magic.FileTypeRPM:
			sigType = "rpm"
		case magic.FileTypeDEB:
			sigType = "deb"
		case magic.FileTypePECOFF:
			sigType = "pe-coff"
		case magic.FileTypePKCS7:
			if blob, err := ioutil.ReadFile(argFile); err != nil {
				return shared.Fail(err)
			} else if authenticode.IsSecurityCatalog(blob) {
				sigType = "cat"
			} else {
				return errors.New("Don't know how to sign this type of file")
			}
		default:
			return errors.New("Don't know how to sign this type of file")
		}
	}
	// open for writing so in-place patch works
	infile, err := os.OpenFile(argFile, os.O_RDWR, 0)
	if err != nil {
		return shared.Fail(err)
	}

	values := url.Values{}
	values.Add("key", argKeyName)
	values.Add("filename", path.Base(argFile))
	if sigType != "" {
		values.Add("sigtype", sigType)
	}
	if fileType == magic.FileTypeDEB && argRole != "" {
		values.Add("deb-role", argRole)
	}
	if err := setDigestQueryParam(values); err != nil {
		return err
	}
	if fileType == magic.FileTypePECOFF && argPageHashes {
		digest, _ := shared.GetDigest()
		if digest != crypto.SHA256 && digest != crypto.SHA1 {
			return errors.New("When --page-hashes is set, SHA1 or SHA256 must be used")
		}
		values.Add("page-hashes", "1")
	}

	response, err := CallRemote("sign", "POST", &values, infile)
	if err != nil {
		return shared.Fail(err)
	}
	defer response.Body.Close()
	if response.Header.Get("Content-Type") == binpatch.MimeType {
		blob, err := ioutil.ReadAll(response.Body)
		if err != nil {
			return shared.Fail(err)
		}
		patch, err := binpatch.Load(blob)
		if err != nil {
			return shared.Fail(err)
		}
		err = patch.Apply(infile, argOutput)
	} else {
		infile.Close()
		err = writeOutput(argOutput, response.Body)
	}
	if err != nil {
		return shared.Fail(err)
	}

	if fileType == magic.FileTypePECOFF {
		f, err := os.OpenFile(argOutput, os.O_RDWR, 0)
		if err != nil {
			return shared.Fail(err)
		}
		defer f.Close()
		if err := authenticode.FixPEChecksum(f); err != nil {
			return shared.Fail(err)
		}
	}

	fmt.Fprintf(os.Stderr, "Signed %s\n", argFile)
	return nil
}

func writeOutput(path string, src io.Reader) error {
	if argOutput == "-" {
		_, err := io.Copy(os.Stdout, src)
		return err
	} else {
		outfile, err := os.Create(path)
		if err != nil {
			return err
		}
		_, err = io.Copy(outfile, src)
		outfile.Close()
		return err
	}
}
