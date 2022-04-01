package dmg

import (
	"bytes"
	"context"
	"crypto"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/sassoftware/relic/v7/lib/binpatch"
	"github.com/sassoftware/relic/v7/lib/certloader"
	"github.com/sassoftware/relic/v7/lib/fruit/csblob"
	"github.com/sassoftware/relic/v7/lib/pkcs9"
)

type SignatureParams struct {
	HashFunc        crypto.Hash
	Requirements    []byte // requirements to embed in signature
	SigningIdentity string
	TeamIdentifier  string
}

func Sign(ctx context.Context, rsfBytes []byte, r io.Reader, cert *certloader.Certificate, params *SignatureParams) (*binpatch.PatchSet, *pkcs9.TimestampedSignature, error) {
	// parse UDIF header
	var rsf udifResourceFile
	if err := binary.Read(bytes.NewReader(rsfBytes), binary.BigEndian, &rsf); err != nil {
		return nil, nil, fmt.Errorf("udif header: %w", err)
	}
	nr := &counter{r: r}
	bundleSize := rsf.XMLOffset + rsf.XMLLength
	oldOffset, oldLength := rsf.SignatureOffset, rsf.SignatureLength
	rsf.SignatureOffset = bundleSize
	blobParams := &csblob.SignatureParams{
		HashFunc:        params.HashFunc,
		Requirements:    params.Requirements,
		SigningIdentity: params.SigningIdentity,
		TeamIdentifier:  params.TeamIdentifier,
		Pages:           io.LimitReader(nr, bundleSize),
		RepSpecific:     rsf.ForHashing(),
	}
	if oldOffset != 0 {
		// provide old signature to copy requirements and flags
		if oldOffset != bundleSize {
			return nil, nil, errors.New("overlap or gap between bundle and signature")
		}
		blobParams.OldSignature = io.LimitReader(nr, oldLength)
	}
	blob, tsig, err := csblob.Sign(ctx, cert, blobParams)
	if err != nil {
		return nil, nil, err
	}
	// drain rest of input file
	if _, err := io.Copy(io.Discard, nr); err != nil {
		return nil, nil, err
	}
	oldSize := nr.n
	// generate patch
	rsf.SignatureLength = int64(len(blob))
	var b bytes.Buffer
	_, _ = b.Write(blob)
	_ = binary.Write(&b, binary.BigEndian, rsf)
	patch := binpatch.New()
	patch.Add(rsf.SignatureOffset, oldSize-rsf.SignatureOffset, b.Bytes())
	// copy values back to params
	params.Requirements = blobParams.Requirements
	params.SigningIdentity = blobParams.SigningIdentity
	params.TeamIdentifier = blobParams.TeamIdentifier
	return patch, tsig, nil
}

type counter struct {
	r io.Reader
	n int64
}

func (c *counter) Read(d []byte) (n int, err error) {
	n, err = c.r.Read(d)
	if n > 0 {
		c.n += int64(n)
	}
	return
}
