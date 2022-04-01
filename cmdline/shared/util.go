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

package shared

import (
	"errors"
	"fmt"
	"os"

	"github.com/sassoftware/relic/v7/config"
	"github.com/sassoftware/relic/v7/lib/dlog"
)

func InitConfig() error {
	return initConfig(false)
}

func InitClientConfig() error {
	return initConfig(true)
}

func initConfig(client bool) error {
	if CurrentConfig != nil {
		return nil
	}
	dlog.SetLevel(ArgDebug)
	usedDefault := false
	if ArgConfig == "" {
		ArgConfig = config.DefaultConfig()
		usedDefault = true
	}
	if client && usedDefault {
		cfg, err := config.FromEnvironment()
		if err != nil {
			return err
		} else if cfg != nil {
			CurrentConfig = cfg
			return nil
		}
	}
	if ArgConfig == "" {
		return errors.New("--config not specified")
	}
	cfg, err := config.ReadFile(ArgConfig)
	if err != nil {
		if os.IsNotExist(err) && usedDefault {
			if client {
				// try to use environment
				cfg, err = config.FromEnvironment()
				if err != nil {
					return err
				} else if cfg != nil {
					CurrentConfig = cfg
					return nil
				}
			}
			return fmt.Errorf("--config not specified and default config at %s does not exist", ArgConfig)
		}
		return err
	}
	CurrentConfig = cfg
	return nil
}

func OpenFile(path string) (*os.File, error) {
	if path == "-" {
		return os.Stdin, nil
	}
	return os.Open(path)
}

func OpenForPatching(inpath, outpath string) (*os.File, error) {
	switch {
	case inpath == "-":
		return os.Stdin, nil
	case inpath == outpath:
		// open for writing so in-place patch works
		return os.OpenFile(inpath, os.O_RDWR, 0)
	default:
		return os.Open(inpath)
	}
}

func Fail(err error) error {
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(70)
	}
	return err
}
