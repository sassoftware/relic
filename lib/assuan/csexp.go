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

package assuan

// http://people.csail.mit.edu/rivest/Sexp.txt

import (
	"bytes"
	"errors"
	"strconv"
)

type csExp struct {
	Value []byte
	Items []*csExp
}

var InvalidCsExp = errors.New("invalid cs-exp")

func parseCsExp(blob []byte) (*csExp, error) {
	root := new(csExp)
	stack := []*csExp{root}
	top := root
csloop:
	for {
		switch {
		case len(blob) == 0:
			if len(stack) > 1 {
				return nil, InvalidCsExp
			}
			break csloop
		case blob[0] == '(':
			item := new(csExp)
			stack = append(stack, item)
			top.Items = append(top.Items, item)
			top = item
			blob = blob[1:]
		case blob[0] == ')':
			if len(stack) < 2 {
				return nil, InvalidCsExp
			}
			stack = stack[:len(stack)-1]
			top = stack[len(stack)-1]
			blob = blob[1:]
		default:
			n := bytes.IndexByte(blob, ':')
			if n < 1 {
				return nil, InvalidCsExp
			}
			length, err := strconv.ParseUint(string(blob[:n]), 10, 64)
			if err != nil || length > uint64(len(blob)-n-1) {
				return nil, InvalidCsExp
			}
			blob = blob[n+1:]
			data := blob[:length]
			blob = blob[length:]
			top.Items = append(top.Items, &csExp{Value: data})
		}
	}
	return root, nil
}
