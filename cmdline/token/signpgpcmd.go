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
	"errors"
	"io"
	"os"
	"strings"

	"gerrit-pdt.unx.sas.com/tools/relic.git/cmdline/shared"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/pgptools"
	"gerrit-pdt.unx.sas.com/tools/relic.git/p11token/pgptoken"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
)

var SignPgpCmd = &cobra.Command{
	Use:   "sign-pgp",
	Short: "Create PGP signatures",
	Long:  "This command is vaguely compatible with the gpg command-line and accepts (and mostly, ignores) many of gpg's options. It can thus be used as a drop-in replacement for tools that use gpg to make signatures.",
	RunE:  signPgpCmd,
}

var (
	argPgpUser      string
	argPgpArmor     bool
	argPgpNoArmor   bool
	argPgpDetached  bool
	argPgpClearsign bool
	argPgpTextMode  bool
	argPgpMiniClear bool
)

func init() {
	shared.RootCmd.AddCommand(SignPgpCmd)
	SignPgpCmd.Flags().StringVarP(&argPgpUser, "local-user", "u", "", "Specify keyname or cfgfile:keyname")
	SignPgpCmd.Flags().StringVarP(&argKeyName, "key", "k", "", "Name of key section in config file to use")
	SignPgpCmd.Flags().StringVarP(&argOutput, "output", "o", "", "Write output to file")
	SignPgpCmd.Flags().BoolVarP(&argPgpArmor, "armor", "a", false, "Create ASCII armored output")
	SignPgpCmd.Flags().BoolVarP(&argPgpTextMode, "textmode", "t", false, "Sign in CRLF canonical text form")
	SignPgpCmd.Flags().BoolVar(&argPgpNoArmor, "no-armor", false, "Create binary output")
	SignPgpCmd.Flags().BoolVarP(&argPgpDetached, "detach-sign", "b", false, "Create a detached signature")
	SignPgpCmd.Flags().BoolVar(&argPgpClearsign, "clearsign", false, "Create a cleartext signature")
	SignPgpCmd.Flags().BoolVar(&argPgpMiniClear, "mini-clear", false, "Create a cleartext signature without the embedded document")

	SignPgpCmd.Flags().BoolP("sign", "s", false, "(ignored)")
	SignPgpCmd.Flags().BoolP("verbose", "v", false, "(ignored)")
	SignPgpCmd.Flags().Bool("no-verbose", false, "(ignored)")
	SignPgpCmd.Flags().BoolP("quiet", "q", false, "(ignored)")
	SignPgpCmd.Flags().Bool("no-secmem-warning", false, "(ignored)")
	SignPgpCmd.Flags().String("digest-algo", "", "(ignored)")
}

func signPgpCmd(cmd *cobra.Command, args []string) (err error) {
	if !argPgpDetached && !argPgpClearsign && !argPgpMiniClear {
		return errors.New("--detach-sign or --clearsign must be set")
	}
	if argKeyName == "" {
		if argPgpUser == "" {
			return errors.New("-u must be set to a keyname or cfgpath:keyname")
		}
		idx := strings.LastIndex(argPgpUser, ":")
		if idx <= 0 {
			argKeyName = argPgpUser
		} else {
			shared.ArgConfig = argPgpUser[:idx]
			argKeyName = argPgpUser[idx+1:]
		}
	}
	key, err := openKey(argKeyName)
	if err != nil {
		return err
	}
	entity, err := pgptoken.KeyFromToken(key)
	if err != nil {
		return err
	}
	config := &packet.Config{}

	var infile *os.File
	if len(args) == 0 || (len(args) == 1 && args[0] == "-") {
		infile = os.Stdin
	} else if len(args) == 1 {
		infile, err = os.Open(args[0])
		if err != nil {
			return err
		}
	} else {
		return errors.New("Expected a single filename argument, or no arguments to read from standard input")
	}
	var out io.WriteCloser
	if argOutput == "" || argOutput == "-" {
		out = os.Stdout
	} else {
		out, err = os.Create(argOutput)
		if err != nil {
			return err
		}
		defer out.Close()
	}

	if argPgpMiniClear {
		err = pgptools.DetachClearSign(out, entity, infile, config)
	} else if argPgpClearsign {
		err = pgptools.ClearSign(out, entity, infile, config)
	} else if argPgpArmor && !argPgpNoArmor {
		if argPgpTextMode {
			err = openpgp.ArmoredDetachSignText(out, entity, infile, nil)
		} else {
			err = openpgp.ArmoredDetachSign(out, entity, infile, nil)
		}
		if err == nil {
			_, err = out.Write([]byte{'\n'})
		}
	} else {
		if argPgpTextMode {
			err = openpgp.DetachSignText(out, entity, infile, nil)
		} else {
			err = openpgp.DetachSign(out, entity, infile, nil)
		}
	}
	return err
}
