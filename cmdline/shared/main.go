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

package shared

import (
	"errors"
	"fmt"
	"os"

	"gerrit-pdt.unx.sas.com/tools/relic.git/config"
	"github.com/spf13/cobra"
)

var argConfig string
var CurrentConfig *config.Config

var RootCmd = &cobra.Command{
	Use: "relic",
}

func init() {
	RootCmd.PersistentFlags().StringVarP(&argConfig, "config", "c", "", "Configuration file")
}

func InitConfig() error {
	if argConfig == "" {
		return errors.New("--config is required")
	}
	config, err := config.ReadFile(argConfig)
	if err != nil {
		return err
	}
	CurrentConfig = config
	return nil
}

func Main() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
