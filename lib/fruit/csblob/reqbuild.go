package csblob

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
)

type reqBuilder struct {
	out bytes.Buffer
	err error
}

func DefaultRequirement(identifier string, certs []*x509.Certificate) ([]byte, error) {
	leaf := certs[0]
	b := new(reqBuilder)
	b.putUint32(1)
	items := []func(){
		b.identifier(identifier),
		b.anchorAppleGeneric(),
		b.certFieldEqual(0, "subject.CN", leaf.Subject.CommonName),
	}
	// find intermediate cert
	for _, cert := range certs[1:] {
		if !bytes.Equal(cert.RawSubject, leaf.RawIssuer) {
			continue
		}
		// look for endorsement for specific signature role
		for _, ext := range cert.Extensions {
			if hasPrefix(ext.Id, Intermediate) {
				items = append(items, b.certExtensionExists(1, ext.Id))
				break
			}
		}
		break
	}
	// build requirement from criteria
	b.and(items...)()
	if b.err != nil {
		return nil, b.err
	}
	i := newSuperItem(csRequirement, b.out.Bytes())
	i.itype = uint32(DesignatedRequirement)
	return marshalSuperBlob(csRequirements, []superItem{i}), nil
}

func (b *reqBuilder) putUint32(v uint32) {
	var d [4]byte
	binary.BigEndian.PutUint32(d[:], v)
	b.out.Write(d[:])
}

func (b *reqBuilder) putData(v []byte) {
	b.putUint32(uint32(len(v)))
	b.out.Write(v)
	n := len(v)
	for n%4 != 0 {
		b.out.WriteByte(0)
		n++
	}
}

func (b *reqBuilder) putOID(oid asn1.ObjectIdentifier) {
	// pack first two digits together
	packed := append(asn1.ObjectIdentifier{oid[0]*40 + oid[1]}, oid[2:]...)
	var out []byte
	for _, v := range packed {
		if v < 0x80 {
			// simple case
			out = append(out, byte(v))
			continue
		}
		// build starting from least-significant word
		var outv []byte
		for {
			outv = append(outv, byte(v&0x7f))
			if v >= 0x80 {
				v >>= 7
			} else {
				break
			}
		}
		// reverse and set MSB on all but the last word
		for i := len(outv) - 1; i >= 0; i-- {
			vv := outv[i]
			if i != 0 {
				vv |= 0x80
			}
			out = append(out, vv)
		}
	}
	b.putData(out)
}

func (b *reqBuilder) and(items ...func()) func() {
	return func() {
		for len(items) > 1 {
			b.putUint32(opAnd)
			items[0]()
			items = items[1:]
		}
		items[0]()
	}
}

func (b *reqBuilder) identifier(v string) func() {
	return func() {
		b.putUint32(opIdent)
		b.putData([]byte(v))
	}
}

func (b *reqBuilder) anchorAppleGeneric() func() {
	return func() {
		b.putUint32(opAppleGenericAnchor)
	}
}

func (b *reqBuilder) certFieldEqual(slot int32, field, value string) func() {
	return func() {
		b.putUint32(opCertField)
		b.putUint32(uint32(slot))
		b.putData([]byte(field))
		b.putUint32(uint32(matchEqual))
		b.putData([]byte(value))
	}
}

func (b *reqBuilder) certExtensionExists(slot int32, oid asn1.ObjectIdentifier) func() {
	return func() {
		b.putUint32(opCertGeneric)
		b.putUint32(uint32(slot))
		b.putOID(oid)
		b.putUint32(uint32(matchExists))
	}
}
