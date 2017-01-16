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

package servecmd

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/debug"
	"golang.org/x/sys/windows/svc/eventlog"
)

const ServiceName = "relic"
const ServiceDisplayName = "Relic"
const ServiceDescription = "Secure package signing service"

type relicService struct {
	name string
	elog debug.Log
}

func RunService(isDebug bool) (err error) {
	name := ServiceName
	var elog debug.Log
	run := debug.Run
	if isDebug {
		elog = debug.New(name)
	} else {
		elog, err = eventlog.Open(name)
		if err != nil {
			return
		}
		run = svc.Run
	}
	defer elog.Close()

	elog.Info(1, fmt.Sprintf("%s: starting service", name))
	service := &relicService{name: name, elog: elog}
	err = run(name, service)
	if err != nil {
		elog.Error(1, fmt.Sprintf("%s: service failed: %s", name, err))
	} else {
		elog.Info(1, fmt.Sprintf("%s: service stopped", name))
	}
	return nil
}

func (s *relicService) Execute(args []string, requests <-chan svc.ChangeRequest, changes chan<- svc.Status) (svcSpecificEC bool, exitCode uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}
	srv, err := MakeServer()
	if err != nil {
		s.elog.Error(1, fmt.Sprintf("%s: failed to start: %s", s.name, err))
		return true, 1
	}
	srv.SetOutput(eventLogger{s.elog})
	status := svc.Status{State: svc.Running, Accepts: accepted}
	changes <- status
	stopped := make(chan error)
	go func() {
		stopped <- srv.Serve()
	}()
	stopNow := make(chan bool)
	go func() {
		<-stopNow
		srv.Close()
	}()
	s.elog.Info(1, fmt.Sprintf("%s: accepting connections", s.name))
	stopping := false
	already := false
loop:
	for {
		select {
		case c := <-requests:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- status
			case svc.Stop, svc.Shutdown:
				status.State = svc.StopPending
				changes <- status
				if already {
					s.elog.Info(1, fmt.Sprintf("%s: stopping immediately", s.name))
					break loop
				} else {
					s.elog.Info(1, fmt.Sprintf("%s: stopping gracefully", s.name))
					close(stopNow)
					already = true
				}
				stopping = true
			default:
				s.elog.Error(1, fmt.Sprintf("%s: unexpected control request #%d", s.name, c.Cmd))
			}
		case err := <-stopped:
			if stopping {
				break loop
			} else {
				s.elog.Error(1, fmt.Sprintf("%s: server stopped: %s", s.name, err))
				return true, 1
			}
		}
	}
	return false, 0
}

type eventLogger struct {
	elog debug.Log
}

// Forward logs to the windows event log
func (e eventLogger) Write(d []byte) (int, error) {
	n := len(d)
	if n > 0 && d[n-1] == '\n' {
		d = d[:n-1]
	}
	msg := string(d)
	if strings.HasPrefix(msg, "error") {
		e.elog.Error(1, string(d))
	} else {
		e.elog.Info(1, string(d))
	}
	return n, nil
}

func runIfService() bool {
	interactive, err := svc.IsAnInteractiveSession()
	if err != nil {
		panic(err)
	}
	if interactive {
		// normal command line
		return false
	}
	// running as a service
	err = RunService(false)
	if err != nil {
		panic(err)
	}
	return true
}
