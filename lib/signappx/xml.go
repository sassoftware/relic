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

package signappx

import (
	"encoding/xml"
	"fmt"
)

const xmlHdr = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"%s\"?>\r\n"

func marshalXML(v interface{}, standalone bool) ([]byte, error) {
	x, err := xml.Marshal(v)
	if err != nil {
		return nil, err
	}
	sstr := "no"
	if standalone {
		sstr = "yes"
	}
	hdr := []byte(fmt.Sprintf(xmlHdr, sstr))
	ret := make([]byte, len(hdr), len(hdr)+len(x))
	copy(ret, hdr)
	ret = append(ret, x...)
	return ret, nil
}
