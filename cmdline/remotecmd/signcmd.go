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
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/sassoftware/relic/v7/cmdline/shared"
	"github.com/sassoftware/relic/v7/signers"
)

var SignCmd = &cobra.Command{
	Use:   "sign",
	Short: "Sign a package using a remote signing server",
	RunE:  signCmd,
}

var (
	argIfUnsigned bool
	argSigType    string
)

func init() {
	RemoteCmd.AddCommand(SignCmd)
	SignCmd.Flags().StringVarP(&argKeyName, "key", "k", "", "Name of key on remote server to use")
	SignCmd.Flags().StringVarP(&argFile, "file", "f", "", "Input file to sign")
	SignCmd.Flags().StringVarP(&argOutput, "output", "o", "", "Output file. Defaults to same as --file.")
	SignCmd.Flags().StringVarP(&argSigType, "sig-type", "T", "", "Specify signature type (default: auto-detect)")
	SignCmd.Flags().BoolVar(&argIfUnsigned, "if-unsigned", false, "Skip signing if the file already has a signature")
	shared.AddDigestFlag(SignCmd)
	shared.AddLateHook(func() {
		signers.MergeFlags(SignCmd)
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
		return shared.Fail(fmt.Errorf("can't sign files of type: %s", mod.Name))
	}
	// parse signer-specific flags
	flags, err := mod.FlagsFromCmdline(cmd.Flags())
	if err != nil {
		return shared.Fail(err)
	}
	infile, err := shared.OpenForPatching(argFile, argOutput)
	if err != nil {
		return shared.Fail(err)
	} else if infile == os.Stdin {
		if !mod.AllowStdin {
			return shared.Fail(errors.New("this signature type does not support reading from stdin"))
		}
	} else {
		defer infile.Close()
	}
	if argIfUnsigned {
		if infile == os.Stdin {
			return shared.Fail(errors.New("cannot use --if-unsigned with standard input"))
		}
		if signed, err := mod.IsSigned(infile); err != nil {
			return shared.Fail(err)
		} else if signed {
			fmt.Fprintf(os.Stderr, "skipping already-signed file: %s\n", argFile)
			return nil
		}
		if _, err := infile.Seek(0, 0); err != nil {
			return shared.Fail(fmt.Errorf("rewinding input file: %w", err))
		}
	}
	// transform input if needed
	hash, err := shared.GetDigest()
	if err != nil {
		return err
	}
	opts := signers.SignOpts{
		Path:  argFile,
		Hash:  hash,
		Flags: flags,
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
	if err := flags.ToQuery(values); err != nil {
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
