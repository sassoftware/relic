package p11token

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUlong(t *testing.T) {
	values := []uint{1, 65537, 0x12345678}
	for _, v := range values {
		b := make([]byte, ulongSize)
		putUlong(b, v)
		vv, err := getUlong(b)
		if assert.NoError(t, err) {
			assert.Equal(t, v, vv)
		}
	}
	raw := [][]byte{
		[]byte("a"),
		[]byte("ab"),
		[]byte("abcd"),
		[]byte("abcdefgh"),
	}
	var expect []uint
	if nativeOrder == binary.LittleEndian {
		expect = []uint{0x61, 0x6261, 0x64636261, 0x6867666564636261}
	} else {
		expect = []uint{0x61, 0x6162, 0x61626364, 0x6162636465666768}
	}
	for i, rawv := range raw {
		vv, err := getUlong(rawv)
		if assert.NoError(t, err) {
			assert.Equal(t, expect[i], vv)
		}
	}
	bad := make([]byte, 9)
	_, err := getUlong(bad)
	if assert.Error(t, err) {
		assert.Equal(t, "unable to parse value as unsigned integer: 000000000000000000", err.Error())
	}
}
