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

package winservice

import (
	"fmt"
	"os"
	"time"

	"gerrit-pdt.unx.sas.com/tools/relic.git/cmdline/servecmd"
	"github.com/spf13/cobra"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

const controlTimeout = 10 * time.Second
const pollInterval = 250 * time.Millisecond

var StartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start service",
}

var StopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop service",
}

var StatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Query service status",
}

var UninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Uninstall service",
}

var controlCmds = []*cobra.Command{StartCmd, StopCmd, StatusCmd, UninstallCmd}

func init() {
	for _, cmd := range controlCmds {
		cmd.RunE = controlCmd
		ServiceCmd.AddCommand(cmd)
	}
}

func controlCmd(cmd *cobra.Command, args []string) error {
	name := servecmd.ServiceName
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(name)
	if err != nil {
		return fmt.Errorf("service %s is not installed", name)
	}
	defer s.Close()
	switch cmd {
	case StartCmd:
		err = startService(s)
	case StopCmd:
		err = stopService(s)
	case StatusCmd:
		err = queryService(s)
	case UninstallCmd:
		err = uninstallService(s)
	default:
		panic("unknown command")
	}
	return err
}

func waitStatus(s *mgr.Service, target svc.State, desc string) error {
	var previous svc.State
	deadline := time.Now().Add(controlTimeout)
	for {
		status, err := s.Query()
		if err != nil {
			return fmt.Errorf("failed to poll service %s status: %s", s.Name, err)
		}
		if status.State != previous {
			fmt.Fprintf(os.Stderr, "%s: %s\n", s.Name, stateNames[status.State])
			previous = status.State
		}
		if status.State == target {
			return nil
		}
		if deadline.Before(time.Now()) {
			return fmt.Errorf("timeout waiting for %s to %s", s.Name, desc)
		}
		time.Sleep(pollInterval)
	}
}

func startService(s *mgr.Service) error {
	// NB: no "service args" are needed because the "cmdline args" were
	// appended when the service was installed. See installCmd.
	err := s.Start()
	if err != nil {
		return err
	}
	return waitStatus(s, svc.Running, "start")
}

func stopService(s *mgr.Service) error {
	_, err := s.Control(svc.Stop)
	if err != nil {
		return err
	}
	return waitStatus(s, svc.Stopped, "stop")
}

func queryService(s *mgr.Service) error {
	status, err := s.Query()
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "%s: %s\n", s.Name, stateNames[status.State])
	return nil
}

func uninstallService(s *mgr.Service) error {
	err := s.Delete()
	if err != nil {
		return err
	}
	err = eventlog.Remove(s.Name)
	if err != nil {
		return fmt.Errorf("RemoveEventLogSource() failed: %s", err)
	}
	fmt.Fprintf(os.Stderr, "Removed service %s", s.Name)
	return nil
}
