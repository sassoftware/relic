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
	"golang.org/x/sys/windows/svc"
)

var stateNames = map[svc.State]string{
	svc.Stopped:         "stopped",
	svc.StartPending:    "start pending",
	svc.StopPending:     "stop pending",
	svc.Running:         "running",
	svc.ContinuePending: "continue pending",
	svc.PausePending:    "pause pending",
	svc.Paused:          "paused",
}

var commandNames = map[svc.Cmd]string{
	svc.Stop:        "stop",
	svc.Pause:       "pause",
	svc.Continue:    "continue",
	svc.Interrogate: "interrogate",
	svc.Shutdown:    "shutdown",
}
