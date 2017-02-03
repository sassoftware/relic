package authenticode

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"debug/pe"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"

	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/pkcs7"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/pkcs9"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/x509tools"
)

type PESignature struct {
	pkcs9.TimestampedSignature
	Indirect  SpcIndirectDataContent
	ImageHash crypto.Hash
}

func VerifyPE(r io.ReaderAt, skipDigests bool) ([]PESignature, error) {
	var m peMarkers
	if err := parseCoffHeader(r, &m); err != nil {
		return nil, err
	}
	if err := findCertTable(r, &m); err != nil {
		return nil, err
	}
	var imageReader io.Reader
	if !skipDigests {
		segments := new(readerList)
		segments.Append(0, m.posCksum)
		segments.Append(m.posCksum+4, m.posDDCert)
		segments.Append(m.posDDCert+8, m.posSections)
		if err := sortSections(r, &m, segments); err != nil {
			return nil, err
		}
		if m.posAfterSec > m.posCerts {
			return nil, fmt.Errorf("certificate table is between sections")
		}
		segments.Append(m.posAfterSec, m.posCerts)
		segments.Append(m.posTrailer, 1<<63-1)
		imageReader = segments.Reader(r)
	}
	sigblob, err := readNAt(r, m.posCerts, int(m.sizeOfCerts))
	if err != nil {
		return nil, err
	}
	return checkSignatures(sigblob, imageReader)
}

func parseCoffHeader(r io.ReaderAt, m *peMarkers) error {
	dosheader, err := readNAt(r, 0, 96)
	if err != nil {
		return err
	}
	if !(dosheader[0] == 'M' && dosheader[1] == 'Z') {
		return errors.New("not a PE file")
	}
	pestart := int64(binary.LittleEndian.Uint32(dosheader[0x3c:]))
	if sign, err := readNAt(r, pestart, 4); err != nil {
		return err
	} else if !(sign[0] == 'P' && sign[1] == 'E' && sign[2] == 0 && sign[3] == 0) {
		return fmt.Errorf("Invalid PE COFF file signature of %v.", sign)
	}
	posCoffHeader := pestart + 4

	var coffHeader pe.FileHeader
	if err := readBinaryAt(r, posCoffHeader, 20, &coffHeader); err != nil {
		return err
	}
	m.posOptHeader = posCoffHeader + 20
	m.sizeOfOpt = int64(coffHeader.SizeOfOptionalHeader)
	m.posSecTbl = m.posOptHeader + m.sizeOfOpt
	m.numSections = int(coffHeader.NumberOfSections)
	return nil
}

func findCertTable(r io.ReaderAt, m *peMarkers) error {
	var optMagic uint16
	if err := readBinaryAt(r, m.posOptHeader, 2, &optMagic); err != nil {
		return err
	}
	var dd pe.DataDirectory
	m.posCksum = m.posOptHeader + 64
	switch optMagic {
	case 0x10b:
		// PE32
		var opt pe.OptionalHeader32
		if err := readBinaryAt(r, m.posOptHeader, m.sizeOfOpt, &opt); err != nil {
			return err
		}
		if opt.NumberOfRvaAndSizes >= 5 {
			dd = opt.DataDirectory[4]
		}
		m.posDDCert = m.posOptHeader + 128
		m.posSections = int64(opt.SizeOfHeaders)
	case 0x20b:
		// PE32+
		var opt pe.OptionalHeader64
		if err := readBinaryAt(r, m.posOptHeader, m.sizeOfOpt, &opt); err != nil {
			return err
		}
		if opt.NumberOfRvaAndSizes >= 5 {
			dd = opt.DataDirectory[4]
		}
		m.posDDCert = m.posOptHeader + 144
		m.posSections = int64(opt.SizeOfHeaders)
	default:
		return errors.New("unrecognized optional header magic")
	}
	if m.posDDCert+8 > m.posSecTbl || dd.Size == 0 {
		return errors.New("image does not contain any signatures")
	}
	m.posCerts = int64(dd.VirtualAddress)
	m.sizeOfCerts = int64(dd.Size)
	m.posTrailer = m.posCerts + m.sizeOfCerts
	return nil
}

func sortSections(r io.ReaderAt, m *peMarkers, segments *readerList) error {
	sr := io.NewSectionReader(r, m.posSecTbl, 40*int64(m.numSections))
	m.posAfterSec = m.posSections
	for i := 0; i < m.numSections; i++ {
		var sh pe.SectionHeader32
		if err := binary.Read(sr, binary.LittleEndian, &sh); err != nil {
			return err
		}
		start := int64(sh.PointerToRawData)
		length := int64(sh.SizeOfRawData)
		segments.Append(start, start+length)
		if start+length > m.posAfterSec {
			m.posAfterSec = start + length
		}
	}
	return nil
}

func checkSignatures(blob []byte, image io.Reader) ([]PESignature, error) {
	values := make(map[crypto.Hash][]byte, 1)
	digesters := make(map[crypto.Hash]hash.Hash, 1)
	writers := make([]io.Writer, 0, 1)
	sigs := make([]PESignature, 0, 1)
	for len(blob) != 0 {
		wLen := binary.LittleEndian.Uint32(blob[:4])
		end := (int(wLen) + 7) / 8 * 8
		size := int(wLen) - 8
		if end > len(blob) || size < 0 {
			return nil, errors.New("invalid certificate table")
		}
		cert := blob[8 : 8+size]
		blob = blob[end:]

		sig, err := checkSignature(cert)
		if err != nil {
			return nil, err
		}
		sigs = append(sigs, *sig)
		if image == nil {
			continue
		}
		imageDigest := sig.Indirect.MessageDigest.Digest
		if existing := values[sig.ImageHash]; existing == nil {
			d := sig.ImageHash.New()
			digesters[sig.ImageHash] = d
			writers = append(writers, d)
			values[sig.ImageHash] = imageDigest
		} else if !hmac.Equal(imageDigest, existing) {
			// they can't both be right...
			return nil, fmt.Errorf("digest mismatch: %x != %x", imageDigest, existing)
		}
	}
	if image != nil {
		if _, err := io.Copy(io.MultiWriter(writers...), image); err != nil {
			return nil, err
		}
		for hash, value := range values {
			calc := digesters[hash].Sum(nil)
			if !hmac.Equal(calc, value) {
				return nil, fmt.Errorf("digest mismatch: %x != %x", calc, value)
			}
		}
	}
	return sigs, nil
}

func checkSignature(der []byte) (*PESignature, error) {
	var psd pkcs7.ContentInfoSignedData
	if rest, err := asn1.Unmarshal(der, &psd); err != nil {
		return nil, err
		// some binaries in the wild seem to have trailing zeroes, probably due
		// to including the alignment padding in the size when it's supposed to
		// be implicit
	} else if len(bytes.TrimRight(rest, "\x00")) != 0 {
		return nil, errors.New("trailing garbage after signature")
	}
	if !psd.Content.ContentInfo.ContentType.Equal(OidSpcIndirectDataContent) {
		return nil, errors.New("not an authenticode signature")
	}
	sig, err := psd.Content.Verify(nil, false)
	if err != nil {
		return nil, err
	}
	ts, err := pkcs9.VerifyOptionalTimestamp(sig)
	if err != nil {
		return nil, err
	}
	var indirect SpcIndirectDataContent
	if err := psd.Content.ContentInfo.Unmarshal(&indirect); err != nil {
		return nil, err
	}
	hash, ok := x509tools.PkixDigestToHash(indirect.MessageDigest.DigestAlgorithm)
	if !ok || !hash.Available() {
		return nil, fmt.Errorf("unsupported hash algorithm %s", indirect.MessageDigest.DigestAlgorithm.Algorithm)
	}
	return &PESignature{
		TimestampedSignature: ts,
		Indirect:             indirect,
		ImageHash:            hash,
	}, nil
}
