package csblob

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"slices"

	"howett.net/plist"
)

// DER type identifiers (class+constructed+number packed into the identifier
// octet) for the subset of ASN.1 Apple uses to encode entitlements.
const (
	derBoolean    = 0x01
	derInteger    = 0x02
	derUTF8String = 0x0c
	derSequence   = 0x30
	derAppPlist   = 0x70 // application class, constructed, tag 16
	derContext16  = 0xb0 // context class, constructed, tag 16
)

// EntitlementDER converts an entitlements plist to the DER encoding that
// codesign embeds alongside the plist form since macOS 12 (special slot -7,
// CSMAGIC_EMBEDDED_ENTITLEMENTS_DER). AMFI logs a deprecation warning for
// signatures carrying only the plist form and a future macOS release will
// reject them.
//
// The scheme, matched byte-for-byte against codesign output: the plist becomes
// APPLICATION 16 {INTEGER 1, <root dict>}, a dict is CONTEXT 16 holding one
// SEQUENCE {UTF8String key, value} per entry sorted bytewise by key, an array
// is a SEQUENCE of values, and leaves use the standard universal types.
// codesign refuses to encode real, date and data values, so they are rejected
// here as well.
func EntitlementDER(entitlement []byte) ([]byte, error) {
	var root any
	if _, err := plist.Unmarshal(entitlement, &root); err != nil {
		return nil, fmt.Errorf("parsing entitlement plist: %w", err)
	}
	dict, ok := root.(map[string]any)
	if !ok {
		return nil, errors.New("entitlement plist root must be a dictionary")
	}
	body, err := derValue(dict)
	if err != nil {
		return nil, err
	}
	return derItem(derAppPlist, append([]byte{derInteger, 1, 1}, body...)), nil
}

func derValue(value any) ([]byte, error) {
	switch v := value.(type) {
	case bool:
		if v {
			return []byte{derBoolean, 1, 0xff}, nil
		}
		return []byte{derBoolean, 1, 0x00}, nil
	case string:
		return derItem(derUTF8String, []byte(v)), nil
	case int64:
		return derInt(v), nil
	case uint64:
		return derUint(v), nil
	case []any:
		var body []byte
		for _, item := range v {
			enc, err := derValue(item)
			if err != nil {
				return nil, err
			}
			body = append(body, enc...)
		}
		return derItem(derSequence, body), nil
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		var body []byte
		for _, k := range keys {
			enc, err := derValue(v[k])
			if err != nil {
				return nil, fmt.Errorf("key %q: %w", k, err)
			}
			entry := append(derItem(derUTF8String, []byte(k)), enc...)
			body = append(body, derItem(derSequence, entry)...)
		}
		return derItem(derContext16, body), nil
	default:
		return nil, fmt.Errorf("value of type %T cannot be DER encoded", value)
	}
}

// derInt encodes the minimal big-endian two's complement form DER requires
func derInt(v int64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(v))
	for len(b) > 1 && ((b[0] == 0x00 && b[1]&0x80 == 0) || (b[0] == 0xff && b[1]&0x80 != 0)) {
		b = b[1:]
	}
	return derItem(derInteger, b)
}

func derUint(v uint64) []byte {
	if v <= math.MaxInt64 {
		return derInt(int64(v))
	}
	// the high bit is set, so a leading zero octet keeps the value positive
	b := make([]byte, 9)
	binary.BigEndian.PutUint64(b[1:], v)
	return derItem(derInteger, b)
}

func derItem(identifier byte, content []byte) []byte {
	n := len(content)
	var item []byte
	switch {
	case n < 0x80:
		item = []byte{identifier, byte(n)}
	case n <= 0xff:
		item = []byte{identifier, 0x81, byte(n)}
	case n <= 0xffff:
		item = []byte{identifier, 0x82, byte(n >> 8), byte(n)}
	case n <= 0xffffff:
		item = []byte{identifier, 0x83, byte(n >> 16), byte(n >> 8), byte(n)}
	default:
		item = []byte{identifier, 0x84, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	}
	return append(item, content...)
}
