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

package apk

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"reflect"
)

// implement the uint32-prefixed structure of a APK Signature Scheme v2 Block
// https://source.android.com/security/apksigning/v2#apk-signature-scheme-v2-block-format

var errTrailingData = errors.New("trailing data after structure")

type apkRaw []byte

// Bytes returns the inner content of the raw item, without the length prefix
func (r apkRaw) Bytes() []byte {
	return []byte(r[4:])
}

var (
	bytesType  = reflect.TypeOf([]byte(nil))
	rawType    = reflect.TypeOf(apkRaw(nil))
	uint32Type = reflect.TypeOf(uint32(0))
)

func unmarshal(blob []byte, dest interface{}) error {
	v := reflect.ValueOf(dest)
	if v.Kind() != reflect.Ptr || v.IsNil() {
		return errors.New("target of unmarshal must be a non-nil pointer")
	}
	v = v.Elem()
	blob, err := unmarshalR(blob, v) //, "x")
	if err != nil {
		return err
	} else if len(blob) != 0 {
		return errTrailingData
	}
	return nil
}

func unmarshalR(blob []byte, v reflect.Value /*, path string*/) ([]byte, error) {
	// scalar types (no prefix)
	switch {
	case v.Type() == uint32Type:
		if len(blob) < 4 {
			return nil, io.ErrUnexpectedEOF
		}
		i := binary.LittleEndian.Uint32(blob)
		//fmt.Printf("%s = 0x%x\n", path, i)
		v.SetUint(uint64(i))
		return blob[4:], nil
	}
	// read uint32 length prefix
	if len(blob) < 4 {
		return nil, io.ErrUnexpectedEOF
	}
	size := int(binary.LittleEndian.Uint32(blob))
	if 4+len(blob) < size {
		return nil, io.ErrUnexpectedEOF
	}
	remainder := blob[4+size:]
	raw := blob[:4+size]
	blob = raw[4:]
	switch {
	case v.Type() == bytesType:
		// []byte
		//fmt.Printf("%s = []byte(\"%x\")\n", path, blob)
		v.SetBytes(blob)
	case v.Type() == rawType:
		// apkRaw (same as above but keep the prefix)
		//fmt.Printf("%s = raw(\"%x\")\n", path, raw)
		v.SetBytes(raw)
	// compound types
	case v.Kind() == reflect.Slice:
		// slice other than []byte
		itemType := v.Type().Elem()
		//fmt.Printf("%s = %s{}\n", path, v.Type())
		v.SetLen(0)
		for len(blob) > 0 {
			var err error
			// append a zero value and unmarshal directly into the slice
			n := v.Len()
			v.Set(reflect.Append(v, reflect.Zero(itemType)))
			blob, err = unmarshalR(blob, v.Index(n)) //, fmt.Sprintf("%s[%d]", path, n))
			if err != nil {
				return nil, err
			}
		}
	case v.Kind() == reflect.Struct:
		// structure
		//fmt.Printf("%s = %s{}\n", path, v.Type())
		for i := 0; i < v.NumField(); i++ {
			var err error
			blob, err = unmarshalR(blob, v.Field(i)) //, fmt.Sprintf("%s.%s", path, v.Type().Field(i).Name))
			if err != nil {
				return nil, err
			}
		}
		if len(blob) > 0 {
			return nil, errTrailingData
		}
	default:
		panic("can't unmarshal type " + v.Type().String())
	}
	return remainder, nil
}

func marshal(src interface{}) (apkRaw, error) {
	v := reflect.ValueOf(src)
	m := new(marshaller)
	if err := m.marshal(v); err != nil {
		return nil, err
	}
	return apkRaw(m.buf), nil
}

type marshaller struct {
	buf []byte
	pos int
}

func (m *marshaller) grow(n int) []byte {
	if cap(m.buf)-m.pos < n {
		buf := make([]byte, 2*cap(m.buf)+n)
		copy(buf, m.buf)
		m.buf = buf
	}
	m.buf = m.buf[:m.pos+n]
	ret := m.buf[m.pos : m.pos+n]
	m.pos += n
	return ret
}

func (m *marshaller) write(d []byte) {
	copy(m.grow(len(d)), d)
}

func (m *marshaller) marshal(v reflect.Value) error {
	if v.Type() == rawType {
		// raw
		m.write(v.Bytes())
		return nil
	}
	// scalar types
	switch {
	case v.Type() == uint32Type:
		binary.LittleEndian.PutUint32(m.grow(4), uint32(v.Uint()))
		return nil
	}
	// prefixed types
	start := m.pos
	m.grow(4)
	switch {
	case v.Type() == bytesType:
		// []byte
		m.write(v.Bytes())
	case v.Kind() == reflect.Slice:
		// slice other than []byte
		for i := 0; i < v.Len(); i++ {
			if err := m.marshal(v.Index(i)); err != nil {
				return err
			}
		}
	case v.Kind() == reflect.Struct:
		// structure
		for i := 0; i < v.NumField(); i++ {
			if err := m.marshal(v.Field(i)); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("can't marshal type %s", v.Type())
	}
	// put prefix
	end := m.pos
	binary.LittleEndian.PutUint32(m.buf[start:], uint32(end-start-4))
	return nil
}
