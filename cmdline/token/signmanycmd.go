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
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/sassoftware/relic/v8/cmdline/shared"
	"github.com/sassoftware/relic/v8/internal/signinit"
	"github.com/sassoftware/relic/v8/lib/certloader"
	"github.com/sassoftware/relic/v8/signers"
)

var SignManyCmd = &cobra.Command{
	Use:   "sign-many",
	Short: "Sign multiple packages at once using a token",
	RunE:  signManyCmd,
}

var (
	margIfUnsigned bool
	margSigType    string
	margFiles      []string
)

func init() {
	shared.RootCmd.AddCommand(SignManyCmd)
	addKeyFlags(SignManyCmd)
	SignManyCmd.Flags().StringArrayVarP(&margFiles, "file", "f", []string{}, "Input file to sign; Can be specified multiple times")
	SignManyCmd.Flags().StringVarP(&argSigType, "sig-type", "T", "", "Specify signature type (default: auto-detect)")
	SignManyCmd.Flags().BoolVar(&argIfUnsigned, "if-unsigned", false, "Skip signing if the file already has a signature")
	shared.AddDigestFlag(SignManyCmd)
	shared.AddLateHook(func() {
		signers.MergeFlags(SignManyCmd)
	})
}

func signFile(mod *signers.Signer, opts *signers.SignOpts, cert *certloader.Certificate, argFile string, argOutput string) error {
	opts.Path = argFile
	infile, err := shared.OpenForPatching(argFile, argOutput)
	if err != nil {
		return shared.Fail(err)
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
	if err := signinit.PublishAudit(opts.Audit); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Signed", argFile)
	return nil
}

func signManyCmd(cmd *cobra.Command, args []string) error {
	if len(margFiles) == 0 || argKeyName == "" {
		return errors.New("--file and --key are required")
	}
	mod, err := signers.ByFile(margFiles[0], argSigType)
	if err != nil {
		return shared.Fail(err)
	}
	if mod.Sign == nil {
		return shared.Fail(fmt.Errorf("can't sign files of type: %s", mod.Name))
	}
	flags, err := mod.FlagsFromCmdline(cmd.Flags())
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
	cert, opts, err := signinit.Init(context.Background(), mod, token, argKeyName, hash, flags)
	if err != nil {
		return shared.Fail(err)
	}

	for _, file := range margFiles {
		err := signFile(mod, opts, cert, file, file)
		if err != nil {
			return err
		}
	}

	return nil
}
