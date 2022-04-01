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

package pgp

// Implementation for the "relic sign-pgp" and "relic remote sign-pgp"
// commands, that sort of looks like gpg arguments so it can be used where gpg
// is. This just transforms the "compatible" arguments into an ordinary sign
// command and calls it.

import (
	"errors"
	"strings"

	"github.com/sassoftware/relic/v7/cmdline/shared"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var (
	argDigest       string
	argOutput       string
	argPgpUser      string
	argPgpArmor     bool
	argPgpDetached  bool
	argPgpClearsign bool
	argPgpTextMode  bool
)

func AddCompatFlags(cmd *cobra.Command) {
	flags := cmd.Flags()
	flags.StringVarP(&argPgpUser, "local-user", "u", "", "Specify keyname or cfgfile:keyname")
	flags.StringVarP(&argOutput, "output", "o", "", "Write output to file")
	flags.BoolVarP(&argPgpArmor, "armor", "a", false, "Create ASCII armored output")
	flags.BoolVarP(&argPgpTextMode, "textmode", "t", false, "Sign in CRLF canonical text form")
	flags.BoolVarP(&argPgpDetached, "detach-sign", "b", false, "Create a detached signature")
	flags.BoolVar(&argPgpClearsign, "clearsign", false, "Create a cleartext signature")
	flags.StringVar(&argDigest, "digest-algo", "", "Digest algorithm")

	flags.BoolP("sign", "s", false, "(ignored)")
	flags.BoolP("verbose", "v", false, "(ignored)")
	flags.Bool("no-armor", false, "(ignored)")
	flags.Bool("no-verbose", false, "(ignored)")
	flags.BoolP("quiet", "q", false, "(ignored)")
	flags.Bool("no-secmem-warning", false, "(ignored)")
	flags.String("status-fd", "", "(ignored)")
	flags.String("logger-fd", "", "(ignored)")
	flags.String("attribute-fd", "", "(ignored)")
}

func CallCmd(src, dest *cobra.Command, args []string) error {
	if argPgpUser == "" {
		return errors.New("-u must be set to a keyname or cfgpath:keyname")
	}
	setFlag(dest.Flags(), "sig-type", "pgp")
	idx := strings.LastIndex(argPgpUser, ":")
	if idx <= 0 {
		setFlag(dest.Flags(), "key", argPgpUser)
	} else {
		setFlag(shared.RootCmd.PersistentFlags(), "config", argPgpUser[:idx])
		setFlag(dest.Flags(), "key", argPgpUser[idx+1:])
	}
	if len(args) == 0 {
		setFlag(dest.Flags(), "file", "-")
	} else if len(args) == 1 {
		setFlag(dest.Flags(), "file", args[0])
	} else {
		return errors.New("expected 0 or 1 argument")
	}
	if argOutput == "" {
		argOutput = "-"
	}
	setFlag(dest.Flags(), "output", argOutput)
	if argPgpArmor {
		setFlag(dest.Flags(), "armor", "true")
	}
	if argPgpTextMode {
		setFlag(dest.Flags(), "textmode", "true")
	}
	if argPgpClearsign {
		setFlag(dest.Flags(), "clearsign", "true")
	} else if !argPgpDetached {
		setFlag(dest.Flags(), "inline", "true")
	}
	if argDigest != "" {
		setFlag(dest.Flags(), "digest", argDigest)
	}
	return dest.RunE(dest, []string{})
}

func setFlag(flags *pflag.FlagSet, name, value string) {
	if err := flags.Set(name, value); err != nil {
		panic(err)
	}
}
