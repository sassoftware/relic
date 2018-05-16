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

package token

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/sassoftware/relic/cmdline/shared"
	"github.com/sassoftware/relic/internal/signinit"
	"github.com/sassoftware/relic/signers"
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
)

func init() {
	shared.RootCmd.AddCommand(SignCmd)
	addKeyFlags(SignCmd)
	SignCmd.Flags().StringVarP(&argFile, "file", "f", "", "Input file to sign")
	SignCmd.Flags().StringVarP(&argOutput, "output", "o", "", "Output file")
	SignCmd.Flags().StringVarP(&argSigType, "sig-type", "T", "", "Specify signature type (default: auto-detect)")
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
	startTime := time.Now()
	mod, err := signers.ByFile(argFile, argSigType)
	if err != nil {
		return shared.Fail(err)
	}
	if mod.Sign == nil {
		return shared.Fail(errors.New("can't sign this type of file"))
	}
	flags, err := mod.GetFlags(cmd.Flags())
	if err != nil {
		return shared.Fail(err)
	}
	hash, err := shared.GetDigest()
	if err != nil {
		return shared.Fail(err)
	}
	token, err := openTokenByKey(argKeyName)
	if err != nil {
		return shared.Fail(err)
	}
	cert, opts, err := signinit.Init(mod, token, argKeyName, hash, flags)
	if err != nil {
		return shared.Fail(err)
	}
	opts.Path = argFile
	infile, err := os.OpenFile(argFile, os.O_RDWR, 0)
	if err != nil {
		return shared.Fail(err)
	}
	defer infile.Close()
	// transform the input, sign the stream, and apply the result
	transform, err := mod.GetTransform(infile, *opts)
	if err != nil {
		return shared.Fail(err)
	}
	stream, err := transform.GetReader()
	if err != nil {
		return shared.Fail(err)
	}
	blob, err := mod.Sign(stream, cert, *opts)
	if err != nil {
		return shared.Fail(err)
	}
	mimeType := opts.Audit.GetMimeType()
	if err := transform.Apply(argOutput, mimeType, bytes.NewReader(blob)); err != nil {
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
	duration := time.Since(startTime)
	opts.Audit.Attributes["perf.elapsed.ms"] = duration.Nanoseconds() / 1e6
	if err := PublishAudit(opts.Audit); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Signed", argFile)
	return nil
}
