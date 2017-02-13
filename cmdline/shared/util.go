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
)

func InitConfig() error {
	if CurrentConfig != nil {
		return nil
	}
	usedDefault := false
	if ArgConfig == "" {
		ArgConfig = config.DefaultConfig()
		if ArgConfig == "" {
			return errors.New("--config not specified")
		}
		usedDefault = true
	}
	config, err := config.ReadFile(ArgConfig)
	if err != nil {
		if os.IsNotExist(err) && usedDefault {
			return fmt.Errorf("--config not specified and default config at %s does not exist", ArgConfig)
		}
		return err
	}
	CurrentConfig = config
	return nil
}

func OpenFile(path string) (*os.File, error) {
	if path == "-" {
		return os.Stdin, nil
	} else {
		return os.Open(path)
	}
}

func Fail(err error) error {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(70)
	}
	return err
}
