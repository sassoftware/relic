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

package config

import (
	"os"
	"path"
)

func DefaultDir() string {
	profile := os.Getenv("USERPROFILE")
	if profile != "" {
		// windows
		return path.Join(profile, "relic")
	}
	home := os.Getenv("HOME")
	if home != "" {
		return path.Join(home, ".config", "relic")
	}
	return ""
}

func DefaultConfig() string {
	filepath := DefaultDir()
	if filepath != "" {
		filepath = path.Join(filepath, "relic.conf")
	}
	return filepath
}
