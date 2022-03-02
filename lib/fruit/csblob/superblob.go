package csblob

import (
	"bytes"
	"encoding/binary"
	"errors"
)

type csMagic uint32

const (
	csEmbeddedSignature csMagic = 0xfade0cc0
	csDetachedSignature csMagic = 0xfade0cc1

	csRequirement    csMagic = 0xfade0c00
	csRequirements   csMagic = 0xfade0c01
	csCodeDirectory  csMagic = 0xfade0c02
	csEntitlement    csMagic = 0xfade7171
	csEntitlementDER csMagic = 0xfade7172
	csBlobWrapper    csMagic = 0xfade0b01
)

// codedirectory.h
var csItypes = map[csMagic]uint32{
	csRequirements:   0x2,
	csEntitlement:    0x5,
	csEntitlementDER: 0x7,
	csBlobWrapper:    0x10000,
}

// codedirectory.h
//nolint:deadcode,varcheck // for doc purposes
const (
	cdInfoSlot           = 1
	cdRequirementsSlot   = 2
	cdResourceDirSlot    = 3
	cdTopDirectorySlot   = 4
	cdEntitlementSlot    = 5
	cdRepSpecificSlot    = 6
	cdEntitlementDERSlot = 7

	cdCodeDirectorySlot           = 0
	cdAlternateCodeDirectorySlots = 0x1000
	cdSignatureSlot               = 0x10000
	cdIdentificationSlot          = 0x10001
	cdTicketSlot                  = 0x10002
)

type superItem struct {
	magic csMagic
	itype uint32
	data  []byte
}

func parseSuper(blob []byte) (magic csMagic, items []superItem, err error) {
	if len(blob) < 12 {
		return 0, nil, errShort
	}
	origLen := len(blob)
	// read magic
	magic = csMagic(binary.BigEndian.Uint32(blob))
	length := binary.BigEndian.Uint32(blob[4:])
	count := int(binary.BigEndian.Uint32(blob[8:]))
	if length < 8 || length > uint32(len(blob)) {
		return 0, nil, errors.New("invalid length in signature blob")
	}
	blob = blob[12:]
	// read indexes
	if len(blob) < 8*count {
		return 0, nil, errShort
	}
	indexes, blob := blob[:8*count], blob[8*count:]
	dataOffset := origLen - len(blob)
	for i := 0; i < count; i++ {
		itype := binary.BigEndian.Uint32(indexes[8*i:])
		offset := int(binary.BigEndian.Uint32(indexes[4+8*i:]))
		offset -= dataOffset
		if offset > len(blob)-8 {
			return 0, nil, errShort
		}
		length := int(binary.BigEndian.Uint32(blob[offset+4:]))
		if offset+length > len(blob) {
			return 0, nil, errShort
		}
		items = append(items, superItem{
			magic: csMagic(binary.BigEndian.Uint32(blob[offset:])),
			itype: itype,
			data:  blob[offset : offset+length],
		})
	}
	return magic, items, nil
}

func newSuperItem(magic csMagic, payload []byte) superItem {
	packed := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint32(packed, uint32(magic))
	binary.BigEndian.PutUint32(packed[4:], uint32(len(payload)+8))
	copy(packed[8:], payload)
	return superItem{
		magic: magic,
		itype: csItypes[magic],
		data:  packed,
	}
}

func marshalSuperBlob(magic csMagic, items []superItem) []byte {
	ints := make([]uint32, 3+2*len(items))
	ints[0] = uint32(magic)
	length := uint32(4 * len(ints))
	ints[2] = uint32(len(items))
	for i, item := range items {
		ints[3+2*i] = item.itype
		ints[4+2*i] = length
		length += uint32(len(item.data))
	}
	ints[1] = length
	b := bytes.NewBuffer(make([]byte, 0, length))
	_ = binary.Write(b, binary.BigEndian, ints)
	for _, item := range items {
		b.Write(item.data)
	}
	return b.Bytes()
}

var errShort = errors.New("short read in signature blob")
