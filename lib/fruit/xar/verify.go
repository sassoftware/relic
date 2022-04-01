package xar

import (
	"crypto"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"sort"
	"strconv"

	"github.com/beevik/etree"
	ber "github.com/go-asn1-ber/asn1-ber"

	"github.com/sassoftware/relic/v7/lib/fruit/csblob"
	"github.com/sassoftware/relic/v7/lib/pkcs7"
	"github.com/sassoftware/relic/v7/lib/pkcs9"
	"github.com/sassoftware/relic/v7/lib/x509tools"
	"github.com/sassoftware/relic/v7/signers/sigerrors"
)

type Signature struct {
	HashFunc     crypto.Hash
	Signature    *pkcs9.TimestampedSignature
	NotaryTicket []byte
}

func (x *XAR) Verify(skipDigests bool) (*Signature, error) {
	var tsig pkcs9.TimestampedSignature
	if x.CMSSignature != nil {
		// repack BER as DER
		pkt, err := ber.DecodePacketErr(x.CMSSignature)
		if err != nil {
			return nil, err
		}
		der := pkt.Bytes()
		psd, err := pkcs7.Unmarshal(der)
		if err != nil {
			return nil, fmt.Errorf("reading CMS signature: %w", err)
		}
		sig, err := psd.Content.Verify(x.TOCHash, false)
		if err != nil {
			return nil, fmt.Errorf("verifying CMS signature: %w", err)
		}
		tsig, err = pkcs9.VerifyOptionalTimestamp(sig)
		if err != nil {
			return nil, err
		}
	} else if x.ClassicSignature != nil {
		pub := x.Certificates[0].PublicKey
		if err := x509tools.Verify(pub, x.HashFunc, x.TOCHash, x.ClassicSignature); err != nil {
			// try again with a hash of a hash, which seems to be found on some older packages
			d := x.HashFunc.New()
			d.Write(x.TOCHash)
			err2 := x509tools.Verify(pub, x.HashFunc, d.Sum(nil), x.ClassicSignature)
			if err2 != nil {
				// use original error
				return nil, fmt.Errorf("verifying RSA signature: %w", err)
			}
		}
		tsig = pkcs9.TimestampedSignature{
			Signature: pkcs7.Signature{
				Certificate:   x.Certificates[0],
				Intermediates: x.Certificates[1:],
			},
		}
	} else {
		return nil, sigerrors.NotSignedError{Type: "xar"}
	}
	if !skipDigests {
		if err := x.checkFiles(); err != nil {
			return nil, err
		}
	}
	// mark proprietary certificate extensions as handled so it doesn't fail the chain
	for _, cert := range tsig.Intermediates {
		csblob.MarkHandledExtensions(cert)
	}
	return &Signature{
		HashFunc:     x.HashFunc,
		Signature:    &tsig,
		NotaryTicket: x.NotaryTicket,
	}, nil
}

func (x *XAR) checkFiles() error {
	// gather all files with checksums into a flat list and sort by offset
	var dataFiles []*tocFile
	gatherDataFiles(x.toc.Files, &dataFiles)
	sort.Slice(dataFiles, func(i, j int) bool { return dataFiles[i].Offset < dataFiles[j].Offset })
	for _, f := range dataFiles {
		if err := checkFile(x.heap, f); err != nil {
			return fmt.Errorf("checksumming %q: %w", f.Name, err)
		}
	}
	return nil
}

func checkFiles(toc *etree.Element, heap io.ReaderAt) error {
	// gather all files with checksums into a flat list and sort by offset
	var dataFiles []*tocFile
	for _, ed := range toc.FindElements("//file/data") {
		ef := ed.Parent()
		ek := ed.SelectElement("archived-checksum")
		if ek == nil {
			continue
		}
		offset, _ := strconv.ParseInt(textOf(ed.SelectElement("offset")), 10, 64)
		length, _ := strconv.ParseInt(textOf(ed.SelectElement("length")), 10, 64)
		f := &tocFile{
			Name:   textOf(ef.SelectElement("name")),
			Offset: offset,
			Length: length,
			ArchivedChecksum: tocFileSum{
				Style:  ek.SelectAttrValue("style", ""),
				Digest: ek.Text(),
			},
		}
		dataFiles = append(dataFiles, f)
	}
	sort.Slice(dataFiles, func(i, j int) bool { return dataFiles[i].Offset < dataFiles[j].Offset })
	for _, f := range dataFiles {
		if err := checkFile(heap, f); err != nil {
			return fmt.Errorf("checksumming %q: %w", f.Name, err)
		}
	}
	return nil
}

func textOf(e *etree.Element) string {
	if e == nil {
		return ""
	}
	return e.Text()
}

func checkFile(heap io.ReaderAt, f *tocFile) error {
	var h hash.Hash
	switch f.ArchivedChecksum.Style {
	case "sha1":
		h = sha1.New()
	case "sha256":
		h = sha256.New()
	case "sha512":
		h = sha512.New()
	default:
		return fmt.Errorf("unsupported hash type %s", f.ArchivedChecksum.Style)
	}
	expected, err := hex.DecodeString(f.ArchivedChecksum.Digest)
	if err != nil {
		return err
	}
	r := io.NewSectionReader(heap, f.Offset, f.Length)
	if n, err := io.Copy(h, r); err != nil {
		return err
	} else if n != f.Length {
		return io.ErrUnexpectedEOF
	}
	calculated := h.Sum(nil)
	if !hmac.Equal(expected, calculated) {
		return fmt.Errorf("digest mismatch: expected %x but got %x", expected, calculated)
	}
	return nil
}

func gatherDataFiles(dirFiles []*tocFile, dataFiles *[]*tocFile) {
	for _, f := range dirFiles {
		if f.Length != 0 {
			*dataFiles = append(*dataFiles, f)
		} else if len(f.Files) != 0 {
			gatherDataFiles(f.Files, dataFiles)
		}
	}
}

type streamReaderAt struct {
	r   io.Reader
	pos int64
}

func (r *streamReaderAt) ReadAt(d []byte, p int64) (int, error) {
	if p > r.pos {
		if _, err := io.CopyN(ioutil.Discard, r.r, p-r.pos); err != nil {
			return 0, err
		}
		r.pos = p
	} else if p < r.pos {
		return 0, fmt.Errorf("attempted to seek backwards: at %d, to %d", r.pos, p)
	}
	n, err := io.ReadFull(r.r, d)
	r.pos += int64(n)
	return n, err
}
