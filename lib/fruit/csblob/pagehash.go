package csblob

import (
	"crypto"
	"fmt"
	"hash"
	"io"
)

type HashType uint8

// CSCommon.h
const (
	HashNone HashType = iota
	HashSHA1
	HashSHA256
	HashSHA256Truncated
	HashSHA384
	HashSHA512
)

func hashFunc(hashType HashType, hashLen uint8) (h crypto.Hash, err error) {
	switch hashType {
	case HashSHA1:
		h = crypto.SHA1
	case HashSHA256:
		h = crypto.SHA256
	case HashSHA384:
		h = crypto.SHA384
	}
	if h == 0 {
		err = fmt.Errorf("unknown hash type %d", err)
	} else if h.Size() != int(hashLen) {
		err = fmt.Errorf("expected size %d for hash %d (%s) but got %d", h.Size(), hashType, h, hashLen)
	}
	return
}

func hashType(h crypto.Hash) (HashType, error) {
	switch h {
	case crypto.SHA1:
		return HashSHA1, nil
	case crypto.SHA256:
		return HashSHA256, nil
	case crypto.SHA384:
		return HashSHA384, nil
	default:
		return 0, fmt.Errorf("unsupported hash type %s", h)
	}
}

func hashPages(hashFuncs []crypto.Hash, pages io.Reader, singlePage bool) (slots [][]byte, slotCount uint32, codeLimit int64, err error) {
	hashers := make([]hash.Hash, len(hashFuncs))
	writers := make([]io.Writer, len(hashFuncs))
	slots = make([][]byte, len(hashFuncs))
	for i, f := range hashFuncs {
		hashers[i] = f.New()
		writers[i] = hashers[i]
	}
	if singlePage {
		codeLimit, err = io.Copy(io.MultiWriter(writers...), pages)
		if err != nil {
			return
		}
		for i, h := range hashers {
			slots[i] = h.Sum(nil)
		}
		slotCount = 1
		return
	}
	buf := make([]byte, 1<<defaultPageSizeLog2)
	for {
		var n int
		n, err = io.ReadFull(pages, buf)
		if n <= 0 {
			if err == io.EOF {
				err = nil
			}
			return
		}
		for i, h := range hashers {
			h.Reset()
			h.Write(buf[:n])
			slots[i] = h.Sum(slots[i])
		}
		codeLimit += int64(n)
		slotCount++
	}
}
