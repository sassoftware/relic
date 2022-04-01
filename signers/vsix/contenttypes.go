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

package vsix

import (
	"fmt"
	"io/ioutil"

	"github.com/sassoftware/relic/v7/lib/zipslicer"
)

func (m *mangler) parseTypes(f *zipslicer.MangleFile) error {
	fc, err := f.Open()
	if err != nil {
		return err
	}
	blob, err := ioutil.ReadAll(fc)
	if err != nil {
		return err
	}
	if err := m.ctypes.Parse(blob); err != nil {
		return fmt.Errorf("parsing %s: %w", f.Name, err)
	}
	return nil
}

func (m *mangler) newCtypes(hasCer bool) error {
	for ext, ctype := range contentTypes {
		if ext == "cer" && !hasCer {
			continue
		}
		m.ctypes.ByExt[ext] = ctype
	}
	contents, err := m.ctypes.Marshal()
	if err != nil {
		return err
	}
	return m.m.NewFile(contentTypesPath, contents)
}
