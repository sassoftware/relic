//
// Copyright (c) SAS Institute Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package authenticode

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/hmac"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"unicode/utf16"

	"github.com/sassoftware/relic/v7/lib/binpatch"
	"github.com/sassoftware/relic/v7/lib/certloader"
	"github.com/sassoftware/relic/v7/lib/pkcs7"
	"github.com/sassoftware/relic/v7/lib/pkcs9"
	"github.com/sassoftware/relic/v7/lib/x509tools"
	"github.com/sassoftware/relic/v7/signers/sigerrors"
)

// Type of signature formatting used for different PowerShell file formats
type PsSigStyle int

const (
	// "Hash" style used by e.g. .ps1 files
	SigStyleHash PsSigStyle = iota + 1
	// XML style used by e.g. .ps1xml files
	SigStyleXML
	// C# style used by .mof files
	SigStyleC
)

var psExtMap = map[string]PsSigStyle{
	".ps1":    SigStyleHash,
	".ps1xml": SigStyleXML,
	".psc1":   SigStyleXML,
	".psd1":   SigStyleHash,
	".psm1":   SigStyleHash,
	".cdxml":  SigStyleXML,
	".mof":    SigStyleC,
}

const psBegin = "SIG # Begin signature block"
const psEnd = "SIG # End signature block"

type sigStyle struct{ start, end string }

var psStyles = map[PsSigStyle]sigStyle{
	SigStyleHash: {"# ", ""},
	SigStyleXML:  {"<!-- ", " -->"},
	SigStyleC:    {"/* ", " */"},
}

// Get the PowerShell signature style for a filename or extension
func GetSigStyle(filename string) (PsSigStyle, bool) {
	style, ok := psExtMap[filepath.Ext(filename)]
	return style, ok
}

// Return all supported PowerShell signature styles
func AllSigStyles() []string {
	var ret []string
	for k := range psExtMap {
		ret = append(ret, k)
	}
	return ret
}

type PsDigest struct {
	Imprint           []byte
	HashFunc          crypto.Hash
	TextSize, SigSize int64
	SigStyle          PsSigStyle
	IsUtf16           bool
}

// Digest a PowerShell script from a stream, returning the sum and the length of the digested bytes.
//
// PowerShell scripts are digested in UTF-16-LE format so, unless already in
// that format, the text is converted first. Existing signatures are discarded.
func DigestPowershell(r io.Reader, style PsSigStyle, hash crypto.Hash) (*PsDigest, error) {
	si, ok := psStyles[style]
	if !ok {
		return nil, errors.New("invalid powershell signature style")
	}
	br := bufio.NewReader(r)
	isUtf16, first, _ := detectUtf16(br, si.start, si.end)
	d := hash.New()
	var textSize, sigSize int64
	var saved string
	for {
		line, err := readLine(br, isUtf16)
		if err != nil && err != io.EOF {
			return nil, err
		}
		if line == first {
			// remove EOL from previous line
			if isUtf16 {
				saved = saved[:len(saved)-4]
				sigSize = 4
			} else {
				saved = saved[:len(saved)-2]
				sigSize = 2
			}
			// count the size of the signature
			sigSize += int64(len(line))
			n, err := io.Copy(io.Discard, br)
			if err != nil {
				return nil, err
			}
			sigSize += n
			break
		} else {
			_ = writeUtf16(d, saved, isUtf16)
			textSize += int64(len(saved))
			saved = line
		}
		if err == io.EOF {
			break
		}
	}
	_ = writeUtf16(d, saved, isUtf16)
	textSize += int64(len(saved))
	return &PsDigest{d.Sum(nil), hash, textSize, sigSize, style, isUtf16}, nil
}

func detectUtf16(br *bufio.Reader, start, end string) (bool, string, string) {
	first := start + psBegin + end + "\r\n"
	last := start + psEnd + end + "\r\n"
	if bom, err := br.Peek(2); err == nil && bom[0] == 0xff && bom[1] == 0xfe {
		// UTF-16-LE
		return true, toUtf16(first), toUtf16(last)
	}
	return false, first, last
}

type PowershellSignature struct {
	pkcs9.TimestampedSignature
	OpusInfo *SpcSpOpusInfo
	HashFunc crypto.Hash
}

// Verify a PowerShell script. The signature "style" must already have been
// determined by calling GetSigStyle
func VerifyPowershell(r io.ReadSeeker, style PsSigStyle, skipDigests bool) (*PowershellSignature, error) {
	si, ok := psStyles[style]
	if !ok {
		return nil, errors.New("invalid powershell signature style")
	}
	br := bufio.NewReader(r)
	isUtf16, first, last := detectUtf16(br, si.start, si.end)
	found := false
	var textSize int64
	var pkcsb bytes.Buffer
	for {
		line, err := readLine(br, isUtf16)
		if err == io.EOF && !found {
			return nil, sigerrors.NotSignedError{Type: "powershell document"}
		} else if err != nil {
			return nil, err
		}
		if found && line == last {
			break
		} else if found {
			lstr := string(line)
			if isUtf16 {
				lstr = fromUtf16(line)
			}
			if !strings.HasPrefix(lstr, si.start) || !strings.HasSuffix(lstr, si.end+"\r\n") {
				return nil, errors.New("malformed powershell signature")
			}
			i := len(si.start)
			j := len(lstr) - len(si.end) - 2
			lder, err := base64.StdEncoding.DecodeString(lstr[i:j])
			if err != nil {
				return nil, err
			}
			pkcsb.Write(lder)
		} else if line == first {
			// remove preceding \r\n from size
			if isUtf16 {
				textSize -= 4
			} else {
				textSize -= 2
			}
			found = true
		} else {
			textSize += int64(len(line))
		}
	}
	psd, err := pkcs7.Unmarshal(pkcsb.Bytes())
	if err != nil {
		return nil, err
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
	indirect := new(SpcIndirectDataContentMsi)
	if err := psd.Content.ContentInfo.Unmarshal(indirect); err != nil {
		return nil, err
	}
	hash, err := x509tools.PkixDigestToHashE(indirect.MessageDigest.DigestAlgorithm)
	if err != nil {
		return nil, err
	}
	if !skipDigests {
		if _, err := r.Seek(0, 0); err != nil {
			return nil, err
		}
		digest, err := DigestPowershell(r, style, hash)
		if err != nil {
			return nil, err
		}
		if !hmac.Equal(digest.Imprint, indirect.MessageDigest.Digest) {
			return nil, fmt.Errorf("digest mismatch: %x != %x", digest.Imprint, indirect.MessageDigest.Digest)
		}
	}
	opus, err := GetOpusInfo(ts.SignerInfo)
	if err != nil {
		return nil, err
	}
	pss := &PowershellSignature{
		TimestampedSignature: ts,
		HashFunc:             hash,
		OpusInfo:             opus,
	}
	return pss, nil
}

// Sign a previously digested PowerShell script and return the Authenticode structure
func (pd *PsDigest) Sign(ctx context.Context, cert *certloader.Certificate, params *OpusParams) (*binpatch.PatchSet, *pkcs9.TimestampedSignature, error) {
	ts, err := SignSip(ctx, pd.Imprint, pd.HashFunc, psSipInfo, cert, params)
	if err != nil {
		return nil, nil, err
	}
	patch, err := pd.MakePatch(ts.Raw)
	if err != nil {
		return nil, nil, err
	}
	return patch, ts, nil
}

// Create a patchset that will add or replace the signature on the digested script
func (pd *PsDigest) MakePatch(sig []byte) (*binpatch.PatchSet, error) {
	si, ok := psStyles[pd.SigStyle]
	if !ok {
		return nil, errors.New("invalid powershell signature style")
	}
	var buf bytes.Buffer
	buf.WriteString("\r\n" + si.start + psBegin + si.end + "\r\n")
	b64 := base64.StdEncoding.EncodeToString(sig)
	for i := 0; i < len(b64); i += 64 {
		j := i + 64
		if j > len(b64) {
			j = len(b64)
		}
		buf.WriteString(si.start + b64[i:j] + si.end + "\r\n")
	}
	buf.WriteString(si.start + psEnd + si.end + "\r\n")
	patch := binpatch.New()
	var encoded []byte
	if pd.IsUtf16 {
		encoded = []byte(toUtf16(buf.String()))
	} else {
		encoded = buf.Bytes()
	}
	patch.Add(pd.TextSize, int64(pd.SigSize), encoded)
	return patch, nil
}

func readLine(br *bufio.Reader, isUtf16 bool) (string, error) {
	line, err := br.ReadString('\n')
	if isUtf16 && err == nil {
		// \n\0
		var zero byte
		zero, err = br.ReadByte()
		if zero != 0 {
			return "", errors.New("malformed utf16")
		}
		line += "\x00"
	}
	return line, err
}

// Convert UTF8 to UTF-16-LE
func toUtf16(x string) string {
	runes := utf16.Encode([]rune(x))
	buf := bytes.NewBuffer(make([]byte, 0, 2*len(runes)))
	_ = binary.Write(buf, binary.LittleEndian, runes)
	return buf.String()
}

// Convert UTF8 to UTF-16-LE and write it to "d"
func writeUtf16(d io.Writer, x string, isUtf16 bool) error {
	if isUtf16 {
		_, err := d.Write([]byte(x))
		return err
	}
	runes := utf16.Encode([]rune(x))
	return binary.Write(d, binary.LittleEndian, runes)
}

// Convert UTF-16-LE to UTF8
func fromUtf16(x string) string {
	runes := make([]uint16, len(x)/2)
	_ = binary.Read(bytes.NewReader([]byte(x)), binary.LittleEndian, runes)
	return string(utf16.Decode(runes))
}
