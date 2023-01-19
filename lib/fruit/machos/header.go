package machos

import (
	"bytes"
	"debug/macho"
	"encoding/binary"
	"errors"
	"io"

	"github.com/sassoftware/relic/v7/lib/binpatch"
)

const (
	loadCmdCodeSignature macho.LoadCmd = 0x1d

	segLinkEdit      = "__LINKEDIT"
	alignSegmentFile = 8
	alignSegmentMem  = 4096
)

type machoMarkers struct {
	macho.FileHeader
	ByteOrder binary.ByteOrder
	Magic     uint32

	// start and length of existing signature
	sigStart int64
	sigLen   int64

	// position of signature loadcmd if present
	loadCsStart int64
	// position of __LINKEDIT segment header
	linkEditHdrPos int64
	// original __LINKEDIT segment header
	linkEditHdr macho.SegmentHeader
	// end of load commands
	nextLc int64
	// start of first section
	firstSh int64
	// size of image without signature
	codeSize int64
}

type codeSigCmd struct {
	Cmd       macho.LoadCmd
	Len       uint32
	SigOffset uint32
	SigLength uint32
}

// scan the header of a mach-o binary, taking note of important offsets in the
// header so that it can be patched
func scanFile(r io.Reader) (*machoMarkers, error) {
	f := new(machoMarkers)
	// Read and decode Mach magic to determine byte order, size.
	// Magic32 and Magic64 differ only in the bottom bit.
	var ident [4]byte
	if _, err := io.ReadFull(r, ident[0:]); err != nil {
		return nil, err
	}
	be := binary.BigEndian.Uint32(ident[0:])
	le := binary.LittleEndian.Uint32(ident[0:])
	switch macho.Magic32 &^ 1 {
	case be &^ 1:
		f.ByteOrder = binary.BigEndian
		f.Magic = be
	case le &^ 1:
		f.ByteOrder = binary.LittleEndian
		f.Magic = le
	default:
		return nil, errors.New("invalid magic number")
	}
	// Read entire file header.
	rr := io.MultiReader(bytes.NewReader(ident[:]), r)
	if err := binary.Read(rr, f.ByteOrder, &f.FileHeader); err != nil {
		return nil, err
	}
	endOfHeader := binary.Size(f.FileHeader)
	if f.Magic == macho.Magic64 {
		// discard reserved field
		_, _ = io.ReadFull(r, ident[:])
		endOfHeader += 4
	}
	dat := make([]byte, f.Cmdsz)
	if _, err := io.ReadFull(r, dat); err != nil {
		return nil, err
	}
	endOfHeader += len(dat)
	f.nextLc = int64(endOfHeader)
	f.firstSh = 1<<63 - 1
	bo := f.ByteOrder
	for i := 0; i < int(f.Ncmd); i++ {
		// Each load command begins with uint32 command and length.
		if len(dat) < 8 {
			return nil, errors.New("command block too small")
		}
		cmd, siz := macho.LoadCmd(bo.Uint32(dat[0:4])), bo.Uint32(dat[4:8])
		if siz < 8 || siz > uint32(len(dat)) {
			return nil, errors.New("invalid command block size")
		}
		cmdPos := int64(endOfHeader - len(dat))
		var cmddat []byte
		cmddat, dat = dat[0:siz], dat[siz:]
		switch cmd {
		case macho.LoadCmdSegment:
			var seg macho.Segment32
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &seg); err != nil {
				return nil, err
			}
			if cstring(seg.Name[:]) == segLinkEdit {
				f.linkEditHdrPos = cmdPos
				f.linkEditHdr = macho.SegmentHeader{
					Addr:   uint64(seg.Addr),
					Memsz:  uint64(seg.Memsz),
					Offset: uint64(seg.Offset),
					Filesz: uint64(seg.Filesz),
				}
			}
			for i := 0; i < int(seg.Nsect); i++ {
				var sh macho.Section32
				if err := binary.Read(b, bo, &sh); err != nil {
					return nil, err
				}
				if sh.Size != 0 && sh.Offset != 0 && int64(sh.Offset) < f.firstSh {
					f.firstSh = int64(sh.Offset)
				}
			}
		case macho.LoadCmdSegment64:
			var seg macho.Segment64
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &seg); err != nil {
				return nil, err
			}
			if cstring(seg.Name[:]) == segLinkEdit {
				f.linkEditHdrPos = cmdPos
				f.linkEditHdr = macho.SegmentHeader{
					Addr:   seg.Addr,
					Memsz:  seg.Memsz,
					Offset: seg.Offset,
					Filesz: seg.Filesz,
				}
			}
			for i := 0; i < int(seg.Nsect); i++ {
				var sh macho.Section64
				if err := binary.Read(b, bo, &sh); err != nil {
					return nil, err
				}
				if seg.Filesz != 0 && sh.Size != 0 && sh.Offset != 0 && int64(sh.Offset) < f.firstSh {
					f.firstSh = int64(sh.Offset)
				}
			}
			// TODO: look for embedded plist
		case loadCmdCodeSignature:
			var sig codeSigCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &sig); err != nil {
				return nil, err
			}
			f.sigStart = int64(sig.SigOffset)
			f.sigLen = int64(sig.SigLength)
			f.loadCsStart = cmdPos
		}
	}
	linkEditEnd := int64(f.linkEditHdr.Offset) + int64(f.linkEditHdr.Filesz)
	if f.sigLen != 0 {
		f.codeSize = f.sigStart
		sigEnd := f.sigStart + f.sigLen
		if sigEnd > linkEditEnd || sigEnd < linkEditEnd-16 {
			return nil, errors.New("old signature is not coterminous with __LINKEDIT segment")
		}
	} else {
		f.codeSize = linkEditEnd
	}
	return f, nil
}

func (f *machoMarkers) PatchSignature(oldHeader []byte, sigSize int64) (newHeader, sigBuf []byte, sigStart int64, patch *binpatch.PatchSet, padding int64, err error) {
	patch = binpatch.New()
	newHeader = oldHeader
	sigStart = f.sigStart
	if f.sigLen >= sigSize {
		// existing block is big enough, overwrite it
		sigBuf = make([]byte, f.sigLen)
		patch.Add(f.sigStart, f.sigLen, sigBuf)
		return
	}
	sigSize = align(sigSize, alignSegmentFile)
	if sigStart == 0 {
		// place signature after the current end of __LINKEDIT
		sigStart = align(f.codeSize, alignSegmentFile)
	}
	// allocate patch buffer for signature
	padding = sigStart - f.codeSize
	padded := make([]byte, padding+sigSize)
	sigBuf = padded[padding:]
	// make room for signature loadcmd if there isn't one already
	newHeader, err = f.patchNcmd(newHeader, patch)
	if err != nil {
		return
	}
	// update __LINKEDIT bounds
	f.patchLinkEdit(newHeader, patch, sigStart, sigSize)
	// write signature loadcmd
	f.patchLoadCmd(newHeader, patch, sigStart, sigSize)
	// record patch now, buffer to be filled by caller
	patch.Add(f.codeSize, f.sigLen, padded)
	return
}

// make room for a new loadcmd
func (f *machoMarkers) patchNcmd(newHeader []byte, patch *binpatch.PatchSet) ([]byte, error) {
	if f.loadCsStart != 0 {
		return newHeader, nil
	}
	f.loadCsStart = f.nextLc
	loadCsEnd := f.nextLc + 16
	if loadCsEnd > f.firstSh {
		return nil, errors.New("mach-o loader cmd for signature would overflow next section")
	}
	if int64(len(newHeader)) < loadCsEnd {
		// extend buffer
		buf := make([]byte, loadCsEnd)
		copy(buf, newHeader)
		newHeader = buf
	}
	// update Ncmd
	f.ByteOrder.PutUint32(newHeader[16:], f.ByteOrder.Uint32(newHeader[16:])+1)
	// update Cmdsz
	f.ByteOrder.PutUint32(newHeader[20:], f.ByteOrder.Uint32(newHeader[20:])+16)
	patch.Add(16, 8, newHeader[16:16+8])
	return newHeader, nil
}

// write loadcmd for signature
func (f *machoMarkers) patchLoadCmd(newHeader []byte, patch *binpatch.PatchSet, sigStart, sigSize int64) {
	f.ByteOrder.PutUint32(newHeader[f.loadCsStart:], uint32(loadCmdCodeSignature))
	f.ByteOrder.PutUint32(newHeader[f.loadCsStart+4:], 16)
	f.ByteOrder.PutUint32(newHeader[f.loadCsStart+8:], uint32(sigStart))
	f.ByteOrder.PutUint32(newHeader[f.loadCsStart+12:], uint32(sigSize))
	patch.Add(f.loadCsStart, 16, newHeader[f.loadCsStart:f.loadCsStart+16])
}

func (f *machoMarkers) patchLinkEdit(newHeader []byte, patch *binpatch.PatchSet, sigStart, sigSize int64) {
	hdr := f.linkEditHdr
	end := uint64(sigStart + sigSize)
	hdr.Filesz = end - hdr.Offset
	hdr.Memsz = uint64(align(int64(end-hdr.Offset), alignSegmentMem))
	var patchStart, patchSize int64
	if f.Magic == macho.Magic64 {
		// update Memsz
		f.ByteOrder.PutUint64(newHeader[f.linkEditHdrPos+32:], hdr.Memsz)
		// update Filesz
		f.ByteOrder.PutUint64(newHeader[f.linkEditHdrPos+48:], hdr.Filesz)
		patchStart, patchSize = f.linkEditHdrPos+32, 24
	} else {
		// update Memsz
		f.ByteOrder.PutUint32(newHeader[f.linkEditHdrPos+28:], uint32(hdr.Memsz))
		// update Filesz
		f.ByteOrder.PutUint32(newHeader[f.linkEditHdrPos+36:], uint32(hdr.Filesz))
		patchStart, patchSize = f.linkEditHdrPos+28, 12
	}
	patch.Add(patchStart, patchSize, newHeader[patchStart:patchStart+patchSize])
}

func cstring(b []byte) string {
	i := bytes.IndexByte(b, 0)
	if i == -1 {
		i = len(b)
	}
	return string(b[0:i])
}

func align(addr, align int64) int64 {
	n := addr % align
	if n != 0 {
		addr += align - n
	}
	return addr
}
