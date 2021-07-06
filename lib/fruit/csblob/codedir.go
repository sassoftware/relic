package csblob

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"errors"
)

type CodeDirectoryHeader struct {
	Magic   csMagic
	Length  uint32
	Version uint32
	Flags   SignatureFlags

	HashOffset       uint32
	IdentOffset      uint32
	SpecialSlotCount uint32
	CodeSlotCount    uint32
	CodeLimit        uint32

	HashSize     uint8
	HashType     HashType
	_            uint8
	PageSizeLog2 uint8
	_            uint32
	// Version >= 0x20100
	ScatterOffset uint32
	// Version >= 0x20200
	TeamOffset uint32
	_          uint32
	// Version >= 0x20300
	CodeLimit64 int64
	// Version >= 0x20400
	ExecSegmentBase  int64
	ExecSegmentLimit int64
	ExecSegmentFlags int64
}

type CodeDirectory struct {
	Header          CodeDirectoryHeader
	SigningIdentity string
	TeamIdentifier  string
	HashFunc        crypto.Hash

	CodeHashes          [][]byte
	ManifestHash        []byte
	RequirementsHash    []byte
	ResourcesHash       []byte
	EntitlementsHash    []byte
	EntitlementsDERHash []byte
	RepSpecificHash     []byte

	Raw    []byte
	CDHash []byte
	IType  uint32
}

type SignatureFlags uint32

// CSCommon.h
const (
	FlagHost              SignatureFlags = 0x000001
	FlagAdhoc             SignatureFlags = 0x000002
	FlagForceHard         SignatureFlags = 0x000100
	FlagForceKill         SignatureFlags = 0x000200
	FlagForceExpiration   SignatureFlags = 0x000400
	FlagRestrict          SignatureFlags = 0x000800
	FlagEnforcement       SignatureFlags = 0x001000
	FlagLibraryValidation SignatureFlags = 0x002000
	FlagRuntime           SignatureFlags = 0x010000
	FlagLinkerSigned      SignatureFlags = 0x020000
)

// don't propagate these to a new signature
const clearFlags = FlagAdhoc | FlagLinkerSigned

func parseCodeDirectory(blob []byte, itype uint32) (*CodeDirectory, error) {
	var hdr CodeDirectoryHeader
	if err := binary.Read(bytes.NewReader(blob), binary.BigEndian, &hdr); err != nil {
		return nil, err
	}
	// zero out fields that aren't present in the current version
	switch {
	case hdr.Version < 0x20100:
		hdr.ScatterOffset = 0
		fallthrough
	case hdr.Version < 0x20200:
		hdr.TeamOffset = 0
		fallthrough
	case hdr.Version < 0x20300:
		hdr.CodeLimit64 = 0
		fallthrough
	case hdr.Version < 0x20400:
		hdr.ExecSegmentBase = 0
		hdr.ExecSegmentFlags = 0
		hdr.ExecSegmentLimit = 0
	}
	dir := &CodeDirectory{
		Header: hdr,
		Raw:    blob,
		IType:  itype,
	}
	// read indirect fields
	var err error
	if hdr.IdentOffset != 0 {
		dir.SigningIdentity, err = cstring(blob, int(hdr.IdentOffset))
		if err != nil {
			return nil, err
		}
	}
	if hdr.TeamOffset != 0 {
		dir.TeamIdentifier, err = cstring(blob, int(hdr.TeamOffset))
		if err != nil {
			return nil, err
		}
	}
	if hdr.ScatterOffset != 0 {
		return nil, errors.New("scatterOffset is not supported")
	}
	dir.HashFunc, err = hashFunc(hdr.HashType, hdr.HashSize)
	if err != nil {
		return nil, err
	}
	// hash over whole directory for signature to use
	h := dir.HashFunc.New()
	h.Write(blob)
	dir.CDHash = h.Sum(nil)
	// read hash slots
	hashBase := int(hdr.HashOffset)
	hashLen := int(hdr.HashSize)
	slot := func(i int) []byte {
		hash := blob[hashBase+i*hashLen : hashBase+(i+1)*hashLen]
		for _, c := range hash {
			if c != 0 {
				return hash
			}
		}
		// all zero
		return nil
	}
	dir.CodeHashes = make([][]byte, hdr.CodeSlotCount)
	for i := 0; i < int(hdr.CodeSlotCount); i++ {
		dir.CodeHashes[i] = slot(i)
	}
	for i := 1; i <= int(hdr.SpecialSlotCount); i++ {
		// special slots are placed before the code slots with an index equal to
		// the negative of their superblob itype
		v := slot(-i)
		switch i {
		case cdInfoSlot:
			dir.ManifestHash = v
		case cdRequirementsSlot:
			dir.RequirementsHash = v
		case cdResourceDirSlot:
			dir.ResourcesHash = v
		case cdEntitlementSlot:
			dir.EntitlementsHash = v
		case cdEntitlementDERSlot:
			dir.EntitlementsDERHash = v
		case cdRepSpecificSlot:
			dir.RepSpecificHash = v
		}
	}
	return dir, nil
}

func cstring(blob []byte, i int) (string, error) {
	if i >= len(blob) {
		return "", errShort
	}
	blob = blob[i:]
	j := bytes.IndexByte(blob, 0)
	if j < 0 {
		return "", errShort
	}
	return string(blob[:j]), nil
}

type codeDirParams struct {
	*SignatureParams
	Specials      [][]byte
	CodeSlots     []byte
	CodeSlotCount uint32
	HashFunc      crypto.Hash
	CodeLimit     int64
	SinglePage    bool
}

type codeDirResult struct {
	Raw      []byte
	Digest   []byte
	HashFunc crypto.Hash
}

func newCodeDirectory(params codeDirParams) (codeDirResult, error) {
	hdr := CodeDirectoryHeader{
		Magic:            csCodeDirectory,
		Version:          0x20300,
		Flags:            params.Flags,
		SpecialSlotCount: uint32(len(params.Specials)),
		CodeSlotCount:    params.CodeSlotCount,
		HashSize:         uint8(params.HashFunc.Size()),
		PageSizeLog2:     defaultPageSizeLog2,
		ExecSegmentBase:  params.ExecSegmentBase,
		ExecSegmentLimit: params.ExecSegmentLimit,
		ExecSegmentFlags: params.ExecSegmentFlags,
	}
	var err error
	hdr.HashType, err = hashType(params.HashFunc)
	if err != nil {
		return codeDirResult{}, err
	}
	if hdr.ExecSegmentBase != 0 || hdr.ExecSegmentLimit != 0 || hdr.ExecSegmentFlags != 0 {
		hdr.Version = 0x20400
	}
	if params.SinglePage {
		// single slot DMG
		hdr.PageSizeLog2 = 0
	}
	// compute special slots
	h := params.HashFunc.New()
	specialSlots := make([]byte, 0, h.Size()*len(params.Specials))
	for _, special := range params.Specials {
		if special != nil {
			h.Reset()
			h.Write(special)
			specialSlots = h.Sum(specialSlots)
		} else {
			specialSlots = specialSlots[:len(specialSlots)+h.Size()]
		}
	}
	// fill out header
	if params.CodeLimit > (1<<31)-2 {
		hdr.CodeLimit64 = params.CodeLimit
	} else {
		hdr.CodeLimit = uint32(params.CodeLimit)
	}
	offset := binary.Size(hdr)
	hdr.IdentOffset = uint32(offset)
	offset += len(params.SigningIdentity) + 1
	if params.TeamIdentifier != "" {
		hdr.TeamOffset = uint32(offset)
		offset += len(params.TeamIdentifier) + 1
	}
	hdr.HashOffset = uint32(offset) + hdr.SpecialSlotCount*uint32(hdr.HashSize)
	offset += len(specialSlots) + len(params.CodeSlots)
	hdr.Length = uint32(offset)
	// marshal
	b := bytes.NewBuffer(make([]byte, 0, offset))
	if err := binary.Write(b, binary.BigEndian, hdr); err != nil {
		return codeDirResult{}, err
	}
	b.WriteString(params.SigningIdentity)
	b.WriteByte(0)
	if params.TeamIdentifier != "" {
		b.WriteString(params.TeamIdentifier)
		b.WriteByte(0)
	}
	b.Write(specialSlots)
	b.Write(params.CodeSlots)
	blob := b.Bytes()
	// compute cd hash
	h.Reset()
	h.Write(blob)
	return codeDirResult{
		Raw:      blob,
		Digest:   h.Sum(nil),
		HashFunc: params.HashFunc,
	}, nil
}
