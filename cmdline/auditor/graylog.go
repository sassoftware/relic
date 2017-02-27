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
	"encoding/json"
	"fmt"
	"time"

	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/audit"
	gelf "github.com/robertkowalski/graylog-golang"
)

type gelfMessage struct {
	Version      string `json:"version"`
	Host         string `json:"host"`
	ShortMessage string `json:"short_message"`
	Timestamp    int64  `json:"timestamp"`
	Level        int    `json:"level"`
}

func logGraylog(info *audit.AuditInfo, rowid int64) {
	if auditConfig.GraylogHostname == "" {
		return
	}
	msg := map[string]interface{}{
		"version":       "1.1",
		"host":          info.Attributes["sig.hostname"],
		"short_message": fmtRow(info, rowid),
		"level":         6, // INFO
	}
	if timestamp, err := time.Parse(time.RFC3339Nano, info.Attributes["sig.timestamp"].(string)); err == nil {
		msg["timestamp"] = timestamp.Unix()
	}
	for k, v := range info.Attributes {
		if v == nil {
			continue
		}
		msg["_"+k] = v
	}
	blob, _ := json.Marshal(msg)
	fmt.Println(string(blob))
	g := gelf.New(gelf.Config{
		GraylogHostname: auditConfig.GraylogHostname,
		GraylogPort:     auditConfig.GraylogPort,
	})
	g.Log(string(blob))
}
