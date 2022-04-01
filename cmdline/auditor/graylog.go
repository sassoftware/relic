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

package auditor

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/sassoftware/relic/v7/lib/audit"
)

func logGraylog(info *audit.Info, rowid int64) error {
	if auditConfig.GraylogURL == "" {
		return nil
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
		// graylog quietly changes dots to underscores, but only after running
		// stream filters. that gets confusing real quickly so change it to
		// underscore now.
		k = strings.ReplaceAll(k, ".", "_")
		msg["_"+k] = v
	}
	blob, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	resp, err := http.Post(auditConfig.GraylogURL, "application/json", bytes.NewReader(blob))
	if err != nil {
		return err
	} else if resp.StatusCode >= 300 {
		return fmt.Errorf("posting to graylog: %s", resp.Status)
	}
	resp.Body.Close()
	return nil
}
