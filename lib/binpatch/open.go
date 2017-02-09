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

package binpatch

import "os"

// Open a file for reading and writing. If passed "-" then returns standard
// input. Returns a function that should be called to close the file.
func OpenFile(path string) (*os.File, func() error, error) {
	noop := func() error { return nil }
	if path == "-" {
		return os.Stdin, noop, nil
	} else {
		f, err := os.OpenFile(path, os.O_RDWR, 0)
		if err != nil {
			return nil, noop, err
		}
		return f, f.Close, nil
	}
}
