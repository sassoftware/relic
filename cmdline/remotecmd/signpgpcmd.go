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
	"io"
	"net/url"
	"os"
	"path"
	"strings"

	"gerrit-pdt.unx.sas.com/tools/relic.git/cmdline/shared"
	"github.com/spf13/cobra"
)

var SignPgpCmd = &cobra.Command{
	Use:   "sign-pgp",
	Short: "Create PGP signatures",
	Long:  "This command is vaguely compatible with the gpg command-line and accepts (and mostly, ignores) many of gpg's options. It can thus be used as a drop-in replacement for tools that use gpg to make signatures.",
	RunE:  signPgpCmd,
}

var (
	argPgpUser     string
	argPgpArmor    bool
	argPgpNoArmor  bool
	argPgpDetached bool
)

func init() {
	RemoteCmd.AddCommand(SignPgpCmd)
	SignPgpCmd.Flags().StringVarP(&argPgpUser, "local-user", "u", "", "Specify keyname or cfgfile:keyname")
	SignPgpCmd.Flags().StringVarP(&argKeyName, "key", "k", "", "Name of key on remote server to use")
	SignPgpCmd.Flags().StringVarP(&argOutput, "output", "o", "", "Write output to file")
	SignPgpCmd.Flags().BoolVarP(&argPgpArmor, "armor", "a", false, "Create ASCII armored output")
	SignPgpCmd.Flags().BoolVar(&argPgpNoArmor, "no-armor", false, "Create binary output")
	SignPgpCmd.Flags().BoolVarP(&argPgpDetached, "detach-sign", "b", false, "Create a detached signature (this must be set)")

	SignPgpCmd.Flags().BoolP("sign", "s", false, "(ignored)")
	SignPgpCmd.Flags().BoolP("verbose", "v", false, "(ignored)")
	SignPgpCmd.Flags().Bool("no-verbose", false, "(ignored)")
	SignPgpCmd.Flags().BoolP("quiet", "q", false, "(ignored)")
	SignPgpCmd.Flags().Bool("no-secmem-warning", false, "(ignored)")
	SignPgpCmd.Flags().String("digest-algo", "", "(ignored)")
}

func signPgpCmd(cmd *cobra.Command, args []string) (err error) {
	if !argPgpDetached {
		return errors.New("--detach-sign must be set")
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
	if err := shared.InitConfig(); err != nil {
		return err
	}
	var infile *os.File
	filename := ""
	if len(args) == 0 || (len(args) == 1 && args[0] == "-") {
		infile = os.Stdin
	} else if len(args) == 1 {
		filename = path.Base(args[0])
		infile, err = os.Open(args[0])
		if err != nil {
			return err
		}
	} else {
		return errors.New("Expected a single filename argument, or no arguments to read from standard input")
	}

	values := url.Values{}
	values.Add("key", argKeyName)
	values.Add("filename", filename)
	values.Add("sigtype", "pgp")
	if argPgpArmor && !argPgpNoArmor {
		values.Add("armor", "1")
	}
	response, err := callRemote("sign", "POST", &values, infile)
	if err != nil {
		return err
	}
	output := os.Stdout
	if argOutput != "" && argOutput != "-" {
		output, err = os.Create(argOutput)
		if err != nil {
			return err
		}
		defer output.Close()
	}
	_, err = io.Copy(output, response.Body)
	return err
}
