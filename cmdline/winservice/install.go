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

package winservice

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/howeyc/gopass"
	"github.com/sassoftware/relic/cmdline/servecmd"
	"github.com/sassoftware/relic/cmdline/shared"
	"github.com/spf13/cobra"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

var InstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Install service",
	RunE:  installCmd,
}

var (
	argManual   bool
	argUser     string
	argPassword string
)

func init() {
	ServiceCmd.AddCommand(InstallCmd)
	InstallCmd.Flags().BoolVarP(&argManual, "manual", "m", false, "Don't start service on boot")
	InstallCmd.Flags().StringVarP(&argUser, "user", "u", "", "Username to start service as, instead of the LOCAL SYSTEM account. If no domain is given then the local system will be provided.")
	InstallCmd.Flags().StringVarP(&argPassword, "password", "p", "", "Password for the specified user. If not supplied then it is prompted.")
}

func findSelf() string {
	prog := os.Args[0]
	path, err := filepath.Abs(prog)
	if err != nil {
		return ""
	}
	_, err = os.Stat(path)
	if os.IsNotExist(err) && filepath.Ext(path) == "" {
		path += ".exe"
		_, err = os.Stat(path)
	}
	if err != nil {
		return ""
	}
	return path
}

func findConf() (string, error) {
	if shared.ArgConfig == "" {
		return "", errors.New("--config is required when installing a service")
	}
	// make sure the config is parseable
	err := shared.InitConfig()
	if err != nil {
		return "", err
	}
	return filepath.Abs(shared.ArgConfig)
}

func installCmd(cmd *cobra.Command, args []string) error {
	name := servecmd.ServiceName
	exePath := findSelf()
	if exePath == "" {
		return errors.New("Unable to determine path to the service executable")
	}
	cfgPath, err := findConf()
	if err != nil {
		return fmt.Errorf("Unable to determine path to the config file: %s", err)
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	svc, err := m.OpenService(name)
	if err == nil {
		svc.Close()
		return fmt.Errorf("service %s already exists", name)
	}
	cfg := mgr.Config{
		DisplayName: servecmd.ServiceDisplayName,
		Description: servecmd.ServiceDescription,
	}
	if argUser != "" {
		if strings.Index(argUser, "\\") < 0 && strings.Index(argUser, "@") < 0 {
			domain, err := windows.ComputerName()
			if err != nil || domain == "" {
				return errors.New("Unable to determine computer name; supply a fully qualified user instead")
			}
			argUser = domain + "\\" + argUser
			fmt.Fprintf(os.Stderr, "Changed user account to %s\n", argUser)
		}
		if argPassword == "" {
			fmt.Fprintf(os.Stderr, "Password for account %s: ", argUser)
			pwd, err := gopass.GetPasswd()
			if err != nil {
				return err
			}
			argPassword = string(pwd)
		}
		cfg.ServiceStartName = argUser
		cfg.Password = argPassword
	}
	if !argManual {
		cfg.StartType = mgr.StartAutomatic
	}
	// NB: these args get appended to the exe path, not passed as "service
	// args" to Execute like the docs say they do. This is fine since they get
	// treated the same way as any other cmdline args.
	svc, err = m.CreateService(name, exePath, cfg, "--config", cfgPath, "serve")
	if err != nil {
		return err
	}
	defer svc.Close()
	err = eventlog.InstallAsEventCreate(name, eventlog.Error|eventlog.Warning|eventlog.Info)
	if err != nil {
		svc.Delete()
		return fmt.Errorf("SetupEventLogSource() failed: %s", err)
	}
	fmt.Fprintf(os.Stderr, "Installed service %s\n", name)
	return nil
}
