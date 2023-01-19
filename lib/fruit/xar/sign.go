package xar

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/beevik/etree"

	"github.com/sassoftware/relic/v7/lib/binpatch"
	"github.com/sassoftware/relic/v7/lib/certloader"
	"github.com/sassoftware/relic/v7/lib/pkcs7"
	"github.com/sassoftware/relic/v7/lib/pkcs9"
)

type SignatureParams struct {
	HashFunc crypto.Hash
}

func Sign(ctx context.Context, r io.Reader, cert *certloader.Certificate, hashType crypto.Hash) (*binpatch.PatchSet, *pkcs9.TimestampedSignature, error) {
	hdr, _, err := parseHeader(r)
	if err != nil {
		return nil, nil, err
	} else if hdr.CompressedSize > 1e6 || hdr.UncompressedSize > 10e6 {
		return nil, nil, errors.New("unreasonably large TOC")
	}
	// parse TOC and remove old signatures, tracking how much heap space they occupied
	doc, err := tocEtree(r, hdr.CompressedSize)
	if err != nil {
		return nil, nil, err
	}
	toc := doc.FindElement("/xar/toc")
	if toc == nil {
		return nil, nil, errors.New("missing xar/toc element")
	}
	origSigSize := removeSigs(toc)
	// reserve space for new signatures and insert elements into TOC
	newSigSize := reserveSignatures(toc, hashType, cert.Chain())
	// verify and discard remaining input files
	heap := &streamReaderAt{r: r}
	if err := checkFiles(toc, heap); err != nil {
		return nil, nil, err
	}
	// move offsets of files in accordance with the change in signature size
	adjustOffsets(doc, newSigSize-origSigSize)
	// encode TOC
	ztocBytes, uncompSize, err := compress(doc)
	if err != nil {
		return nil, nil, err
	}
	// write new header and TOC
	newByteLen := 28 + len(ztocBytes) + int(newSigSize)
	newBytes := bytes.NewBuffer(make([]byte, 0, newByteLen))
	tssig, err := appendSignatures(ctx, newBytes, ztocBytes, uncompSize, newSigSize, cert, hashType)
	if err != nil {
		return nil, nil, err
	}
	// patch signature into result
	origTotal := 28 + hdr.CompressedSize + origSigSize
	p := binpatch.New()
	p.Add(0, origTotal, newBytes.Bytes())
	return p, tssig, nil
}

func tocEtree(r io.Reader, compressedSize int64) (*etree.Document, error) {
	origBytes, err := decompress(io.LimitReader(r, compressedSize))
	if err != nil {
		return nil, err
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(origBytes); err != nil {
		return nil, err
	}
	return doc, nil
}

// remove checksum and signatures and return the heap size they occupied
func removeSigs(toc *etree.Element) (size int64) {
	for _, key := range []string{"checksum", "signature", "x-signature"} {
		for _, el := range toc.SelectElements(key) {
			se := el.SelectElement("size")
			if se != nil {
				n, _ := strconv.ParseInt(se.Text(), 10, 64)
				size += n
			}
			el.Parent().RemoveChild(el)
		}
	}
	return
}

// add space for new signatures and return the heap space required for them
func reserveSignatures(toc *etree.Element, hashType crypto.Hash, certs []*x509.Certificate) (newSigSize int64) {
	hashName := strings.ReplaceAll(strings.ToLower(hashType.String()), "-", "")
	// encode cert chain
	var b strings.Builder
	certText := make([]string, len(certs))
	for i, cert := range certs {
		buf := make([]byte, base64.StdEncoding.EncodedLen(len(cert.Raw)))
		base64.StdEncoding.Encode(buf, cert.Raw)
		b.Reset()
		for len(buf) > 72 {
			b.Write(buf[:72])
			b.WriteByte('\n')
			buf = buf[72:]
		}
		b.Write(buf)
		certText[i] = b.String()
	}
	// reserve space for checksum
	cksumSize := int64(hashType.Size())
	cksumEl := newSigElement("checksum", hashName, newSigSize, cksumSize, nil)
	toc.InsertChildAt(0, cksumEl)
	newSigSize += cksumSize
	added := 1
	// reserve space for classic signature
	if n, ok := certs[0].PublicKey.(*rsa.PublicKey); ok {
		classicSize := int64(n.Size())
		classicEl := newSigElement("signature", "RSA", newSigSize, classicSize, certText)
		toc.InsertChildAt(added, classicEl)
		newSigSize += classicSize
		added++
	}
	// reserve space for CMS
	cmsSize := int64(6144)
	for _, cert := range certs {
		cmsSize += int64(len(cert.Raw))
	}
	cmsEl := newSigElement("x-signature", "CMS", newSigSize, cmsSize, certText)
	toc.InsertChildAt(added, cmsEl)
	newSigSize += cmsSize
	return
}

// create one signature element
func newSigElement(key, style string, offset, size int64, certs []string) *etree.Element {
	el := etree.NewElement(key)
	el.CreateAttr("style", style)
	se := etree.NewElement("size")
	se.SetText(strconv.FormatInt(size, 10))
	el.AddChild(se)
	off := etree.NewElement("offset")
	off.SetText(strconv.FormatInt(offset, 10))
	el.AddChild(off)
	if certs != nil {
		keyInfo := etree.NewElement("KeyInfo")
		keyInfo.CreateAttr("xmlns", "http://www.w3.org/2000/09/xmldsig#")
		x5d := etree.NewElement("X509Data")
		keyInfo.AddChild(x5d)
		for _, cert := range certs {
			x5c := etree.NewElement("X509Certificate")
			x5c.SetText(cert)
			x5d.AddChild(x5c)
		}
		el.AddChild(keyInfo)
	}
	return el
}

func adjustOffsets(doc *etree.Document, delta int64) {
	for _, offsetEl := range doc.FindElements("//data/offset") {
		offset, err := strconv.ParseInt(offsetEl.Text(), 10, 64)
		if err != nil {
			continue
		}
		offset += delta
		offsetEl.SetText(strconv.FormatInt(offset, 10))
	}
}

func compress(doc *etree.Document) ([]byte, int64, error) {
	var b bytes.Buffer
	zw := zlib.NewWriter(&b)
	uncompSize, err := doc.WriteTo(zw)
	if err != nil {
		return nil, 0, err
	}
	if err := zw.Close(); err != nil {
		return nil, 0, err
	}
	return b.Bytes(), uncompSize, nil
}

func appendSignatures(ctx context.Context, out *bytes.Buffer, ztoc []byte, uncompSize, reservedSigSize int64, cert *certloader.Certificate, hashType crypto.Hash) (*pkcs9.TimestampedSignature, error) {
	// write file header
	hdr := fileHeader{
		Magic:            xarMagic,
		HeaderSize:       28,
		Version:          1,
		UncompressedSize: uncompSize,
		CompressedSize:   int64(len(ztoc)),
	}
	switch hashType {
	case crypto.SHA1:
		hdr.HashType = hashSHA1
	case crypto.SHA256:
		hdr.HashType = hashSHA256
	case crypto.SHA512:
		hdr.HashType = hashSHA512
	default:
		return nil, fmt.Errorf("unsupported hash type %s", hashType)
	}
	_ = binary.Write(out, binary.BigEndian, hdr)
	out.Write(ztoc)
	// write checksum
	var usedSigSize int64
	d := hashType.New()
	d.Write(ztoc)
	ztocHash := d.Sum(nil)
	out.Write(ztocHash)
	usedSigSize += int64(len(ztocHash))
	// classic signature
	if _, ok := cert.Leaf.PublicKey.(*rsa.PublicKey); ok {
		classicBytes, err := cert.Signer().Sign(rand.Reader, ztocHash, hashType)
		if err != nil {
			return nil, fmt.Errorf("signing xar TOC: %w", err)
		}
		out.Write(classicBytes)
		usedSigSize += int64(len(classicBytes))
	}
	// CMS signature
	builder := pkcs7.NewBuilder(cert.Signer(), cert.Chain(), hashType)
	if err := builder.SetContentData(ztocHash); err != nil {
		return nil, err
	}
	psd, err := builder.Sign()
	if err != nil {
		return nil, err
	}
	tssig, err := pkcs9.TimestampAndMarshal(ctx, psd, cert.Timestamper, false)
	if err != nil {
		return nil, err
	}
	if _, err := psd.Detach(); err != nil {
		return nil, err
	}
	tssig.Raw, err = psd.Marshal()
	if err != nil {
		return nil, err
	}
	out.Write(tssig.Raw)
	usedSigSize += int64(len(tssig.Raw))
	if usedSigSize > reservedSigSize {
		return nil, fmt.Errorf("signature overflows reserved space: have %d bytes, need %d", reservedSigSize, usedSigSize)
	} else {
		// pad out remaining space
		out.Write(make([]byte, reservedSigSize-usedSigSize))
	}
	return tssig, nil
}
