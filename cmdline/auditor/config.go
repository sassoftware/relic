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

package auditor

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"sort"
	"strings"

	"gerrit-pdt.unx.sas.com/tools/relic.git/config"
	"gopkg.in/yaml.v2"
)

type AuditConfig struct {
	ConfigDir   string
	DatabaseUri string
	LogFile     string
	GraylogUrl  string
	CaCert      string
}

var auditConfig AuditConfig

func readConfig() error {
	if argConfigFile == "" {
		return errors.New("--config is required")
	}
	blob, err := ioutil.ReadFile(argConfigFile)
	if err != nil {
		return err
	}
	if err := yaml.Unmarshal(blob, &auditConfig); err != nil {
		return err
	}
	if auditConfig.ConfigDir == "" {
		return errors.New("ConfigDir must be set in configuration file")
	}
	return nil
}

func getServerConfs() ([]*config.Config, error) {
	dir, err := os.Open(auditConfig.ConfigDir)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	names, err := dir.Readdirnames(-1)
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	var confs []*config.Config
	for _, name := range names {
		if strings.HasSuffix(name, ".yml") {
			cpath := path.Join(auditConfig.ConfigDir, name)
			cfg, err := config.ReadFile(cpath)
			if err != nil {
				return nil, fmt.Errorf("%s: %s", cpath, err)
			}
			if cfg.Amqp == nil || cfg.Amqp.Url == "" {
				return nil, fmt.Errorf("%s has no amqp server", cpath)
			}
			confs = append(confs, cfg)
		}
	}
	return confs, nil
}
