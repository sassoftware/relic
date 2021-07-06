package csblob

import (
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode"
)

type RequirementType uint32

// CSCommon.h
const (
	HostRequirement RequirementType = iota + 1
	GuestRequirement
	DesignatedRequirement
	LibraryRequirement
	PluginRequirement
)

func (t RequirementType) String() string {
	switch t {
	case HostRequirement:
		return "host"
	case GuestRequirement:
		return "guest"
	case DesignatedRequirement:
		return "designated"
	case LibraryRequirement:
		return "library"
	case PluginRequirement:
		return "plugin"
	default:
		return fmt.Sprintf("/*unknown type*/ %d", uint32(t))
	}
}

type Requirements map[RequirementType]*Requirement

type Requirement struct {
	Raw []byte
}

func (b *SigBlob) Requirements() (Requirements, error) {
	magic, items, err := parseSuper(b.RawRequirements)
	if err != nil {
		return nil, fmt.Errorf("internal requirements: %w", err)
	}
	if magic != csRequirements {
		return nil, errors.New("internal requirements: bad magic")
	}
	reqs := make(Requirements)
	for _, item := range items {
		reqs[RequirementType(item.itype)] = &Requirement{Raw: item.data[8:]}
	}
	return reqs, nil
}

func (r Requirements) Dump(w io.Writer) error {
	for reqType, req := range r {
		formatted, err := req.Format()
		if err != nil {
			return fmt.Errorf("%s: %w", reqType, err)
		}
		fmt.Fprintln(w, reqType, "=>", formatted)
	}
	return nil
}

func (r *Requirement) Format() (string, error) {
	d := &reqDumper{buf: r.Raw}
	if n, ok := d.getUint32(); !ok {
		return "", d.err
	} else if n != 1 {
		return "", fmt.Errorf("unsupported requirement format %d", n)
	}
	d.op(levelTop)
	if d.err != nil {
		return "", d.err
	}
	return d.out.String(), nil
}

type reqDumper struct {
	buf []byte
	out strings.Builder
	err error
}

func (d *reqDumper) getUint32() (uint32, bool) {
	if len(d.buf) < 4 {
		d.err = io.ErrUnexpectedEOF
		return 0, false
	}
	n := binary.BigEndian.Uint32(d.buf)
	d.buf = d.buf[4:]
	return n, true
}

func (d *reqDumper) getInt32() (int32, bool) {
	n, ok := d.getUint32()
	return int32(n), ok
}

func (d *reqDumper) op(level syntaxLevel) {
	if d.err != nil {
		return
	}
	op, ok := d.getUint32()
	if !ok {
		return
	}
	opN := opCode(op &^ opFlagMask)
	switch opN {
	case opFalse:
		d.out.WriteString("never")
	case opTrue:
		d.out.WriteString("always")
	case opIdent:
		d.out.WriteString("identifier ")
		d.data()
	case opAppleAnchor:
		d.out.WriteString("anchor apple")
	case opAppleGenericAnchor:
		d.out.WriteString("anchor apple generic")
	case opAnchorHash:
		d.out.WriteString("certificate")
		d.certSlot()
		d.out.WriteString(" = ")
		d.hashData()
	case opInfoKeyValue:
		d.out.WriteString("info[")
		d.dotString()
		d.out.WriteString("] = ")
		d.data()
	case opAnd:
		if level < levelAnd {
			d.out.WriteByte('(')
		}
		d.op(levelAnd)
		d.out.WriteString(" and ")
		d.op(levelAnd)
		if level < levelAnd {
			d.out.WriteByte(')')
		}
	case opOr:
		if level < levelOr {
			d.out.WriteByte('(')
		}
		d.op(levelOr)
		d.out.WriteString(" or ")
		d.op(levelOr)
		if level < levelOr {
			d.out.WriteByte(')')
		}
	case opNot:
		d.out.WriteString("! ")
		d.op(levelPrimary)
	case opCDHash:
		d.out.WriteString("cdhash ")
		d.hashData()
	case opInfoKeyField:
		d.out.WriteString("info[")
		d.dotString()
		d.out.WriteByte(']')
		d.match()
	case opEntitlementField:
		d.out.WriteString("entitlement[")
		d.dotString()
		d.out.WriteByte(']')
		d.match()
	case opCertField:
		d.out.WriteString("certificate")
		d.certSlot()
		d.out.WriteByte('[')
		d.dotString()
		d.out.WriteByte(']')
		d.match()
	case opCertFieldDate:
		d.out.WriteString("certificate")
		d.certSlot()
		d.out.WriteString("[timestamp.")
		d.oidData()
		d.out.WriteByte(']')
	case opCertGeneric:
		d.out.WriteString("certificate")
		d.certSlot()
		d.out.WriteString("[field.")
		d.oidData()
		d.out.WriteByte(']')
		d.match()
	case opCertPolicy:
		d.out.WriteString("certificate")
		d.certSlot()
		d.out.WriteString("[policy.")
		d.oidData()
		d.out.WriteByte(']')
		d.match()
	case opTrustedCert:
		d.out.WriteString("certificate")
		d.certSlot()
		d.out.WriteString("trusted")
	case opTrustedCerts:
		d.out.WriteString("anchor trusted")
	case opNamedAnchor:
		d.out.WriteString("anchor apple ")
		d.data()
	case opNamedCode:
		d.out.WriteByte('(')
		d.data()
		d.out.WriteByte(')')
	case opPlatform:
		n, ok := d.getInt32()
		if !ok {
			return
		}
		fmt.Fprintf(&d.out, "platform = %d", n)
		d.buf = d.buf[4:]
	case opNotarized:
		d.out.WriteString("notarized")
	case opLegacyDevID:
		d.out.WriteString("legacy")
	default:
		switch {
		case op&opGenericFalse != 0:
			fmt.Fprintf(&d.out, " false /* opcode %d */", opN)
		case op&opGenericSkip != 0:
			fmt.Fprintf(&d.out, " /* opcode %d */", opN)
		default:
			d.err = fmt.Errorf("unrecognized opcode %d", opN)
			return
		}
	}
}

func (d *reqDumper) getData() []byte {
	length, ok := d.getUint32()
	if !ok {
		return nil
	}
	aligned := length
	if n := length % 4; n != 0 {
		aligned += 4 - n
	}
	if uint32(len(d.buf)) < aligned {
		d.err = io.ErrUnexpectedEOF
		return nil
	}
	v := d.buf[:length]
	d.buf = d.buf[aligned:]
	return v
}

func (d *reqDumper) certSlot() {
	n, ok := d.getInt32()
	if !ok {
		return
	}
	switch n {
	case 0:
		d.out.WriteString(" leaf")
	case -1:
		d.out.WriteString(" root")
	default:
		fmt.Fprintf(&d.out, " %d", n)
	}
}

func (d *reqDumper) match() {
	n, ok := d.getUint32()
	if !ok {
		return
	}
	switch matchOp(n) {
	case matchExists:
		d.out.WriteString(" /* exists */")
	case matchAbsent:
		d.out.WriteString(" absent ")
	case matchEqual:
		d.out.WriteString(" = ")
		d.data()
	case matchContains:
		d.out.WriteString(" ~ ")
		d.data()
	case matchBeginsWith:
		d.out.WriteString(" = ")
		d.data()
		d.out.WriteByte('*')
	case matchEndsWith:
		d.out.WriteString(" = *")
		d.data()
	case matchLessThan:
		d.out.WriteString(" < ")
		d.data()
	case matchGreaterEqual:
		d.out.WriteString(" >= ")
		d.data()
	case matchLessEqual:
		d.out.WriteString(" <= ")
		d.data()
	case matchGreaterThan:
		d.out.WriteString(" > ")
		d.data()

	case matchOn:
		d.out.WriteString(" = ")
		d.timestamp()
	case matchBefore:
		d.out.WriteString(" < ")
		d.timestamp()
	case matchAfter:
		d.out.WriteString(" > ")
		d.timestamp()
	case matchOnOrBefore:
		d.out.WriteString(" <= ")
		d.timestamp()
	case matchOnOrAfter:
		d.out.WriteString(" >= ")
		d.timestamp()
	default:
		d.err = fmt.Errorf("unrecognized match opcode %d", n)
	}
}

func (d *reqDumper) dataExt(dotOK bool) {
	v := d.getData()
	if len(v) == 0 {
		if d.err == nil {
			d.out.WriteString("\"\"")
		}
		return
	}
	simple, printable := true, true
scan:
	for i, vv := range v {
		switch {
		case vv == '.' && dotOK:
			// simple
		case vv >= '0' && vv <= '9':
			if i == 0 {
				// can't start with a digit
				simple = false
			}
		case vv >= 'a' && vv <= 'z' || vv >= 'A' && vv <= 'Z':
			// simple
		case vv < 128 && unicode.IsGraphic(rune(vv)):
			simple = false
		default:
			printable = false
			simple = false
			break scan
		}
	}
	switch {
	case simple:
		d.out.Write(v)
	case printable:
		d.out.WriteByte('"')
		for _, vv := range v {
			if vv == '"' || vv == '\\' {
				d.out.WriteByte('\\')
			}
			d.out.WriteByte(vv)
		}
		d.out.WriteByte('"')
	default:
		fmt.Fprintf(&d.out, "0x%x", v)
	}
}

func (d *reqDumper) data()      { d.dataExt(false) }
func (d *reqDumper) dotString() { d.dataExt(true) }

func (d *reqDumper) hashData() {
	fmt.Fprintf(&d.out, "H\"%x\"", d.getData())
}

func (d *reqDumper) oidData() {
	buf := d.getData()
	var oid asn1.ObjectIdentifier
	for len(buf) > 0 {
		var n int
		for len(buf) > 0 {
			var x byte
			x, buf = buf[0], buf[1:]
			n |= int(x &^ 0x80)
			if x&0x80 == 0 {
				break
			} else {
				n <<= 7
			}
		}
		if len(oid) == 0 {
			// first two digits are packed together
			n1 := n / 40
			n2 := n - n1*40
			oid = append(oid, n1, n2)
		} else {
			oid = append(oid, n)
		}
	}
	d.out.WriteString(oid.String())
}

func (d *reqDumper) timestamp() {
	if len(d.buf) < 8 {
		d.err = io.ErrUnexpectedEOF
		return
	}
	n := binary.BigEndian.Uint64(d.buf)
	d.buf = d.buf[8:]
	epoch := int64(n) + time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC).Unix()
	t := time.Unix(epoch, 0).UTC()
	d.out.Write(t.AppendFormat(nil, "<2006-01-02 15:04:05Z>"))
}

type opCode uint32

// requirement.h
const (
	opFalse = iota
	opTrue
	opIdent
	opAppleAnchor
	opAnchorHash
	opInfoKeyValue
	opAnd
	opOr
	opCDHash
	opNot
	opInfoKeyField
	opCertField
	opTrustedCert
	opTrustedCerts
	opCertGeneric
	opAppleGenericAnchor
	opEntitlementField
	opCertPolicy
	opNamedAnchor
	opNamedCode
	opPlatform
	opNotarized
	opCertFieldDate
	opLegacyDevID

	opFlagMask     = 0xff000000
	opGenericFalse = 0x80000000
	opGenericSkip  = 0x40000000
)

type matchOp uint32

const (
	matchExists matchOp = iota
	matchEqual
	matchContains
	matchBeginsWith
	matchEndsWith
	matchLessThan
	matchGreaterThan
	matchLessEqual
	matchGreaterEqual
	matchOn
	matchBefore
	matchAfter
	matchOnOrBefore
	matchOnOrAfter
	matchAbsent
)

type syntaxLevel int

const (
	levelPrimary = iota
	levelAnd
	levelOr
	levelTop
)
