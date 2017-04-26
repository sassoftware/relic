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
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	"gerrit-pdt.unx.sas.com/tools/relic.git/cmdline/shared"
	"gerrit-pdt.unx.sas.com/tools/relic.git/signers"
	"github.com/spf13/cobra"
)

var SignCmd = &cobra.Command{
	Use:   "sign",
	Short: "Sign a package using a remote signing server",
	RunE:  signCmd,
}

var argSigType string

func init() {
	RemoteCmd.AddCommand(SignCmd)
	SignCmd.Flags().StringVarP(&argKeyName, "key", "k", "", "Name of key on remote server to use")
	SignCmd.Flags().StringVarP(&argFile, "file", "f", "", "Input file to sign")
	SignCmd.Flags().StringVarP(&argOutput, "output", "o", "", "Output file. Defaults to same as --file.")
	SignCmd.Flags().StringVarP(&argSigType, "sig-type", "T", "", "Specify signature type (default: auto-detect)")
	shared.AddDigestFlag(SignCmd)
	shared.AddLateHook(func() {
		signers.MergeFlags(SignCmd.Flags())
	})
}

func signCmd(cmd *cobra.Command, args []string) (err error) {
	if argFile == "" || argKeyName == "" {
		return errors.New("--file and --key are required")
	}
	if argOutput == "" {
		argOutput = argFile
	}
	// detect signature type
	mod, err := signers.ByFile(argFile, argSigType)
	if err != nil {
		return shared.Fail(err)
	}
	if mod.Sign == nil {
		return shared.Fail(errors.New("can't sign this type of file"))
	}
	// parse signer-specific flags
	flags, err := mod.GetFlags(cmd.Flags())
	if err != nil {
		return shared.Fail(err)
	}
	var infile *os.File
	if argFile == "-" {
		if !mod.AllowStdin {
			return shared.Fail(errors.New("this signature type does not support reading from stdin"))
		}
		infile = os.Stdin
	} else {
		// open for writing so in-place patch works
		if argOutput == argFile {
			infile, err = os.OpenFile(argFile, os.O_RDWR, 0)
		} else {
			infile, err = os.Open(argFile)
		}
		if err != nil {
			return shared.Fail(err)
		}
		defer infile.Close()
	}
	// transform input if needed
	hash, err := shared.GetDigest()
	if err != nil {
		return err
	}
	opts := signers.SignOpts{
		Path:         argFile,
		Hash:         hash,
		Flags:        flags,
		FlagOverride: make(map[string]string),
	}
	transform, err := mod.GetTransform(infile, opts)
	if err != nil {
		return shared.Fail(err)
	}
	// build request
	values := url.Values{}
	values.Add("key", argKeyName)
	values.Add("filename", filepath.Base(argFile))
	values.Add("sigtype", mod.Name)
	if err := mod.FlagsToQuery(cmd.Flags(), opts.FlagOverride, values); err != nil {
		return shared.Fail(err)
	}
	if err := setDigestQueryParam(values); err != nil {
		return err
	}
	// do request
	response, err := CallRemote("sign", "POST", &values, transform)
	if err != nil {
		return shared.Fail(err)
	}
	defer response.Body.Close()
	// apply the result
	if err := transform.Apply(argOutput, response.Header.Get("Content-Type"), response.Body); err != nil {
		return shared.Fail(err)
	}
	// if needed, do a final fixup step
	if mod.Fixup != nil {
		f, err := os.OpenFile(argOutput, os.O_RDWR, 0)
		if err != nil {
			return shared.Fail(err)
		}
		defer f.Close()
		if err := mod.Fixup(f); err != nil {
			return shared.Fail(err)
		}
	}

	fmt.Fprintf(os.Stderr, "Signed %s\n", argFile)
	return nil
}
