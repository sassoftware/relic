package xar

import (
	"compress/zlib"
	"crypto"
	"crypto/hmac"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
)

type XAR struct {
	HashFunc         crypto.Hash
	TOCHash          []byte
	Certificates     []*x509.Certificate
	ClassicSignature []byte
	CMSSignature     []byte
	NotaryTicket     []byte

	toc  *tocToc
	heap io.ReaderAt
}

func Open(r io.ReaderAt, size int64) (*XAR, error) {
	hdr, hashType, err := parseHeader(io.NewSectionReader(r, 0, 28))
	if err != nil {
		return nil, err
	}
	base := int64(hdr.HeaderSize)
	toc, tocHash, err := parseTOC(io.NewSectionReader(r, base, hdr.CompressedSize), hashType)
	if err != nil {
		return nil, err
	}
	base += hdr.CompressedSize
	if toc.Checksum.Size != int64(hashType.Size()) {
		return nil, errors.New("checksum is missing or invalid")
	}
	checkHash := make([]byte, toc.Checksum.Size)
	if _, err := r.ReadAt(checkHash, base+toc.Checksum.Offset); err != nil {
		return nil, fmt.Errorf("checksum: %w", err)
	}
	if !hmac.Equal(checkHash, tocHash) {
		return nil, errors.New("checksum mismatch in TOC")
	}
	s := &XAR{
		HashFunc: hashType,
		TOCHash:  tocHash,
		toc:      toc,
		heap:     io.NewSectionReader(r, base, 1<<62),
	}
	if toc.Signature != nil {
		s.ClassicSignature = make([]byte, toc.Signature.Size)
		if _, err := r.ReadAt(s.ClassicSignature, base+toc.Signature.Offset); err != nil {
			return nil, fmt.Errorf("reading signature: %w", err)
		}
		s.Certificates, err = parseCertificates(toc.Signature)
		if err != nil {
			return nil, fmt.Errorf("reading signature: %w", err)
		}
	}
	if toc.XSignature != nil {
		s.CMSSignature = make([]byte, toc.XSignature.Size)
		if _, err := r.ReadAt(s.CMSSignature, base+toc.XSignature.Offset); err != nil {
			return nil, fmt.Errorf("reading CMS signature: %w", err)
		}
	}
	lo := lastOffset(toc.Files) + base
	if trailer := size - lo; trailer > 0 && trailer < 1e6 {
		ticket := make([]byte, trailer)
		if _, err := r.ReadAt(ticket, lo); err != nil {
			return nil, fmt.Errorf("reading trailer: %w", err)
		}
		s.NotaryTicket = ticket
	}
	return s, nil
}

func parseHeader(r io.Reader) (hdr fileHeader, hashType crypto.Hash, err error) {
	if err := binary.Read(r, binary.BigEndian, &hdr); err != nil {
		return fileHeader{}, 0, err
	}
	if hdr.Magic != xarMagic {
		return fileHeader{}, 0, errors.New("incorrect magic")
	} else if hdr.Version != 1 {
		return fileHeader{}, 0, fmt.Errorf("unsupported xar version %d", hdr.Version)
	}
	switch hdr.HashType {
	case hashSHA1:
		hashType = crypto.SHA1
	case hashSHA256:
		hashType = crypto.SHA256
	case hashSHA512:
		hashType = crypto.SHA512
	default:
		return fileHeader{}, 0, fmt.Errorf("unknown hash algorithm %d", hdr.HashType)
	}
	return
}

func decompress(r io.Reader) ([]byte, error) {
	zr, err := zlib.NewReader(r)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(zr)
}

func parseTOC(r io.Reader, hashType crypto.Hash) (*tocToc, []byte, error) {
	tocHash := hashType.New()
	r = io.TeeReader(r, tocHash)
	decomp, err := decompress(r)
	if err != nil {
		return nil, nil, fmt.Errorf("decompressing TOC: %W", err)
	}
	toc := new(tocXar)
	if err := xml.Unmarshal(decomp, toc); err != nil {
		return nil, nil, fmt.Errorf("decoding TOC: %w", err)
	}
	return &toc.TOC, tocHash.Sum(nil), nil
}

func parseCertificates(sig *tocSignature) ([]*x509.Certificate, error) {
	if len(sig.Certificates) == 0 {
		return nil, errors.New("no certificates found")
	}
	parsed := make([]*x509.Certificate, len(sig.Certificates))
	for i, cert := range sig.Certificates {
		certBytes, err := base64.StdEncoding.DecodeString(cert)
		if err != nil {
			return nil, err
		}
		parsed[i], err = x509.ParseCertificate(certBytes)
		if err != nil {
			return nil, err
		}
	}
	return parsed, nil
}

func lastOffset(files []*tocFile) (end int64) {
	for _, f := range files {
		if fileEnd := f.Offset + f.Length; fileEnd > end {
			end = fileEnd
		}
		if subEnd := lastOffset(f.Files); subEnd > end {
			end = subEnd
		}
	}
	return
}
