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
	"io/ioutil"
	"net/url"
	"os"

	"gerrit-pdt.unx.sas.com/tools/relic.git/signrpm"
	"github.com/spf13/cobra"
)

var SignRpmRemoteCmd = &cobra.Command{
	Use:   "sign-rpm",
	Short: "Sign a RPM using a remote signing server",
	RunE:  signRpmRemote,
}

func init() {
	RemoteCmd.AddCommand(SignRpmRemoteCmd)
	SignRpmRemoteCmd.Flags().StringVarP(&argKeyName, "key", "k", "", "name of key on remote server to use")
	SignRpmRemoteCmd.Flags().StringVarP(&argFile, "file", "f", "", "Input RPM file to sign")
	SignRpmRemoteCmd.Flags().StringVarP(&argOutput, "output", "o", "", "Output RPM file")
}

func signRpmRemote(cmd *cobra.Command, args []string) (err error) {
	if argFile == "" || argKeyName == "" {
		return errors.New("--file and --key are required")
	}
	var rpmfile *os.File
	if argFile == "-" {
		rpmfile = os.Stdin
	} else {
		rpmfile, err = os.Open(argFile)
		if err != nil {
			return err
		}
	}
	values := url.Values{}
	values.Add("key", argKeyName)
	response, err := callRemote("sign_rpm", "POST", &values, rpmfile)
	if err != nil {
		return err
	}
	blob, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return err
	}
	if argOutput == "" {
		argOutput = argFile
	}
	rpmfile.Seek(0, 0)
	info, err := signrpm.SignRpmFileWithJson(rpmfile, argOutput, blob)
	if err != nil {
		return err
	}
	info.KeyName = argKeyName
	fmt.Fprintf(os.Stderr, "%s\n", info)
	return nil
}
