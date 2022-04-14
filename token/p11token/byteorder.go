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

package p11token

import (
	"encoding/binary"
	"fmt"
	"unsafe"
)

var (
	nativeOrder binary.ByteOrder
	ulongSize   int
)

func init() {
	var i uint32 = 0x1
	bs := (*[4]byte)(unsafe.Pointer(&i))
	if bs[0] == 0 {
		nativeOrder = binary.BigEndian
	} else {
		nativeOrder = binary.LittleEndian
	}
	var j uint
	ulongSize = int(unsafe.Sizeof(j))
}

func putUlong(buf []byte, v uint) {
	switch ulongSize {
	case 4:
		nativeOrder.PutUint32(buf, uint32(v))
	case 8:
		nativeOrder.PutUint64(buf, uint64(v))
	default:
		panic("can't determine native integer size")
	}
}

func getUlong(value []byte) (uint, error) {
	switch len(value) {
	case 8:
		return uint(nativeOrder.Uint64(value)), nil
	case 4:
		return uint(nativeOrder.Uint32(value)), nil
	case 2:
		return uint(nativeOrder.Uint16(value)), nil
	case 1:
		return uint(value[0]), nil
	}
	return 0, IntegerError{Raw: value}
}

type IntegerError struct {
	Raw []byte
}

func (e IntegerError) Error() string {
	return fmt.Sprintf("unable to parse value as unsigned integer: %x", e.Raw)
}
