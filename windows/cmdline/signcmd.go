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

package cmdline

import (
	"errors"
	"os"
	"os/exec"

	"github.com/spf13/cobra"
)

var SignCmd = &cobra.Command{
	Use:   "sign",
	Short: "Sign a package using a preconfigured tool",
	RunE:  signCmd,
}

var (
	argKeyName string
	argFile    string
)

func init() {
	RootCmd.AddCommand(SignCmd)
	SignCmd.Flags().StringVarP(&argFile, "file", "f", "", "Input file to sign")
	SignCmd.Flags().StringVarP(&argKeyName, "key", "k", "", "name of key section in config file to use")
}

func signCmd(cmd *cobra.Command, args []string) (err error) {
	if argKeyName == "" || argFile == "" {
		return errors.New("--key and --file are required")
	}
	if err := initConfig(); err != nil {
		return err
	}
	cmdline, err := currentConfig.GetToolCmd(argKeyName, argFile)
	if err != nil {
		return err
	}
	process := exec.Command(cmdline[0], cmdline[1:]...)
	process.Stdout = os.Stdout
	process.Stderr = os.Stderr
	return process.Run()
}
