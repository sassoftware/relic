package dmg

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
)

type DMG struct {
	r          io.ReaderAt
	udifOffset int64
	sigBlob    []byte

	rsf udifResourceFile
}

func Open(f *os.File) (*DMG, error) {
	// read and parse UDIF header
	udifOffset, err := f.Seek(-512, io.SeekEnd)
	if err != nil {
		return nil, err
	}
	d := &DMG{r: f, udifOffset: udifOffset}
	if err := binary.Read(f, binary.BigEndian, &d.rsf); err != nil {
		return nil, err
	}
	if d.rsf.Signature != udifSignature {
		return nil, errors.New("dmg file magic not found")
	}
	// read and parse signature
	if d.rsf.SignatureLength != 0 {
		if d.rsf.SignatureLength > 10e6 {
			return nil, fmt.Errorf("unreasonably large dmg signature of %d bytes", d.rsf.SignatureLength)
		}
		d.sigBlob = make([]byte, d.rsf.SignatureLength)
		if _, err := f.ReadAt(d.sigBlob, d.rsf.SignatureOffset); err != nil {
			return nil, err
		}
	}
	return d, nil
}

const udifSignature = 0x6B6F6C79 // koly

type udifFlags uint32

type udifResourceFile struct {
	Signature  uint32
	Version    uint32
	HeaderSize uint32
	Flags      udifFlags

	RunningDataForkOffset int64
	DataForkOffset        int64
	DataForkLength        int64
	ResourceForkOffset    int64
	ResourceForkLength    int64

	SegmentNumber uint32
	SegmentCount  uint32
	SegmentID     [4]uint32

	DataForkChecksum udifChecksum

	XMLOffset int64
	XMLLength int64
	_         [64]byte

	SignatureOffset int64
	SignatureLength int64
	_               [40]byte

	MasterChecksum udifChecksum

	ImageVariant uint32
	SectorCount  int64

	_ [3]uint32
}

// serialize with zeroed signature length for hashing
func (rsf udifResourceFile) ForHashing() []byte {
	rsf.SignatureLength = 0
	var b bytes.Buffer
	_ = binary.Write(&b, binary.BigEndian, rsf)
	return b.Bytes()
}

type udifChecksum struct {
	Type uint32
	Size uint32
	Data [32]uint32 // TODO
}
