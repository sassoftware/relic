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

package isologger

import (
	"io"
	"log"
	"strings"
	"time"
)

const RFC3339Milli = "2006-01-02T15:04:05.000Z07:00" // RFC3339 with 3 decimal places, padded

type isoLogger struct {
	io.Writer
	format string
}

// Configure the logger to emit formatted timestamps to the given writer. The
// format string must always produce output that is no longer than the format
// string itself, otherwise behavior is undefined. If logger is nil, then the
// default logger is updated.
func SetOutput(logger *log.Logger, w io.Writer, format string) {
	// make the prefix big enough to hold the timestamp
	prefix := strings.Repeat(" ", len(format)+1)
	output := isoLogger{Writer: w, format: format}
	if logger == nil {
		log.SetFlags(0)
		log.SetPrefix(prefix)
		log.SetOutput(output)
	} else {
		logger.SetFlags(0)
		logger.SetPrefix(prefix)
		logger.SetOutput(output)
	}
}

func (i isoLogger) Write(d []byte) (int, error) {
	// scribble timestamp over the prefix. this is violating the Writer
	// contract but only logger is going to call this anyway.
	ts := time.Now().Format(i.format)
	copy(d, ts)
	// shift everything left if the formatted string was shorter
	if len(ts) != len(i.format) {
		d = append(d[:len(ts)], d[len(i.format):]...)
	}
	return i.Writer.Write(d)
}
