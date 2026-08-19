package csblob

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func plistWithValue(value string) []byte {
	const format = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>key</key>
	%s
</dict>
</plist>`
	return fmt.Appendf(nil, format, value)
}

// expected values were captured from Apple codesign output (via the
// rcodesign apple_der_entitlements_encoding test corpus)
func TestEntitlementDER(t *testing.T) {
	t.Parallel()
	prefix := []byte{0x70, 15, 2, 1, 1, 0xb0, 10, 0x30, 8, 0x0c, 3, 'k', 'e', 'y'}
	withValue := func(value ...byte) []byte {
		out := append([]byte{}, prefix...)
		out[1] = byte(12 + len(value))
		out[6] = byte(7 + len(value))
		out[8] = byte(5 + len(value))
		return append(out, value...)
	}
	tests := []struct {
		name     string
		plist    string
		expected []byte
	}{
		{"bool-false", "<false/>", withValue(1, 1, 0)},
		{"bool-true", "<true/>", withValue(1, 1, 255)},
		{"integer-0", "<integer>0</integer>", withValue(2, 1, 0)},
		{"integer-neg1", "<integer>-1</integer>", withValue(2, 1, 255)},
		{"integer-1", "<integer>1</integer>", withValue(2, 1, 1)},
		{"integer-42", "<integer>42</integer>", withValue(2, 1, 42)},
		{"integer-wide", "<integer>128</integer>", withValue(2, 2, 0, 128)},
		{"string-empty", "<string></string>", withValue(12, 0)},
		{"string-value", "<string>value</string>", withValue(12, 5, 'v', 'a', 'l', 'u', 'e')},
		{"array-empty", "<array/>", withValue(48, 0)},
		{"array-false", "<array><false/></array>", withValue(48, 3, 1, 1, 0)},
		{"array-true-foo", "<array><true/><string>foo</string></array>", withValue(48, 8, 1, 1, 255, 12, 3, 'f', 'o', 'o')},
		{"dict-empty", "<dict/>", withValue(176, 0)},
		{
			"dict-bool", "<dict><key>inner</key><false/></dict>",
			withValue(176, 12, 48, 10, 12, 5, 'i', 'n', 'n', 'e', 'r', 1, 1, 0),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			der, err := EntitlementDER(plistWithValue(tc.plist))
			require.NoError(t, err)
			assert.Equal(t, tc.expected, der)
		})
	}
}

func TestEntitlementDEREmptyDict(t *testing.T) {
	t.Parallel()
	der, err := EntitlementDER([]byte(`<plist version="1.0"><dict/></plist>`))
	require.NoError(t, err)
	assert.Equal(t, []byte{0x70, 5, 2, 1, 1, 0xb0, 0}, der)
}

// keys must come out bytewise sorted regardless of plist order
func TestEntitlementDERSortsKeys(t *testing.T) {
	t.Parallel()
	der, err := EntitlementDER([]byte(`<plist version="1.0"><dict>
		<key>key3</key><integer>42</integer>
		<key>key</key><false/>
		<key>key2</key><true/>
	</dict></plist>`))
	require.NoError(t, err)
	expected := []byte{
		0x70, 37, 2, 1, 1, 0xb0, 32,
		0x30, 8, 0x0c, 3, 'k', 'e', 'y', 1, 1, 0,
		0x30, 9, 0x0c, 4, 'k', 'e', 'y', '2', 1, 1, 255,
		0x30, 9, 0x0c, 4, 'k', 'e', 'y', '3', 2, 1, 42,
	}
	assert.Equal(t, expected, der)
}

func TestEntitlementDERRejectsUnsupportedTypes(t *testing.T) {
	t.Parallel()
	for _, value := range []string{
		"<real>1.5</real>",
		"<date>2026-01-01T00:00:00Z</date>",
		"<data>Zm9v</data>",
	} {
		_, err := EntitlementDER(plistWithValue(value))
		assert.Error(t, err, value)
	}
	_, err := EntitlementDER([]byte(`<plist version="1.0"><string>not a dict</string></plist>`))
	assert.Error(t, err)
}

func TestEntitlementDERLongForm(t *testing.T) {
	t.Parallel()
	der, err := EntitlementDER(plistWithValue("<string>" + strings.Repeat("a", 200) + "</string>"))
	require.NoError(t, err)
	// 200 content bytes force the long 0x81 length form on the string and on
	// every wrapper above it
	assert.Equal(t, []byte{0x70, 0x81, 217}, der[:3])
	assert.Equal(t, []byte{0x0c, 0x81, 200}, der[17:20])
	assert.Len(t, der, 220)
}
