package machos

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"

	"github.com/sassoftware/relic/v7/lib/binpatch"
	"github.com/sassoftware/relic/v7/lib/certloader"
	"github.com/sassoftware/relic/v7/lib/fruit/csblob"
	"github.com/sassoftware/relic/v7/lib/pkcs9"
)

func Sign(ctx context.Context, r io.Reader, cert *certloader.Certificate, params *csblob.SignatureParams) (*binpatch.PatchSet, *pkcs9.TimestampedSignature, error) {
	var saved bytes.Buffer
	tee := io.TeeReader(r, &saved)
	markers, err := scanFile(tee)
	if err != nil {
		return nil, nil, err
	}
	headerBuf := saved.Bytes()
	// estimate size of signature
	estimatedSize := markers.codeSize * int64(20+params.HashFunc.Size()) / 4096
	estimatedSize += int64(len(params.Entitlement) + len(params.Requirements))
	estimatedSize += 16384
	// patch header to make space
	oldHeaderSize := len(headerBuf)
	headerBuf, sigBuf, sigStart, patch, padding, err := markers.PatchSignature(headerBuf, estimatedSize)
	if err != nil {
		return nil, nil, err
	}
	// if PatchSignature extended the header then the bytes that its extension
	// replaced haven't been read yet, so discard them now
	if extended := len(headerBuf) - oldHeaderSize; extended > 0 {
		if _, err := io.ReadFull(r, make([]byte, extended)); err != nil {
			return nil, nil, err
		}
	}
	// splice the patched header with the rest of the stream
	params.Pages = io.LimitReader(io.MultiReader(bytes.NewReader(headerBuf), r, bytes.NewReader(make([]byte, padding))), sigStart)
	if markers.sigLen != 0 {
		// read the old signature after the pages are hashed
		params.OldSignature = io.LimitReader(r, markers.sigLen)
	}
	blob, tsig, err := csblob.Sign(ctx, cert, params)
	if err != nil {
		return nil, nil, err
	}
	// fill patch buffer with signature
	if len(blob) > len(sigBuf) {
		return nil, nil, fmt.Errorf("signature overflows reserved space: have %d bytes, need %d", len(sigBuf), len(blob))
	}
	copy(sigBuf, blob)
	// discard remainder of stream
	if _, err := io.Copy(ioutil.Discard, r); err != nil {
		return nil, nil, err
	}
	return patch, tsig, nil
}
