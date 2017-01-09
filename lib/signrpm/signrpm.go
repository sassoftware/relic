/*
 * Copyright (c) SAS Institute Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package signrpm

import (
	"crypto"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/sassoftware/go-rpmutils"
	"golang.org/x/crypto/openpgp/packet"
)

type SigInfo struct {
	Header      *rpmutils.RpmHeader
	Fingerprint string
	Timestamp   time.Time
	KeyName     string
	ClientName  string
	ClientIP    string
}

func defaultOpts(opts *rpmutils.SignatureOptions) *rpmutils.SignatureOptions {
	var newOpts rpmutils.SignatureOptions
	if opts != nil {
		newOpts = *opts
	}
	if newOpts.Hash == 0 {
		newOpts.Hash = crypto.SHA256
	}
	if newOpts.CreationTime.IsZero() {
		newOpts.CreationTime = time.Now().UTC().Round(time.Second)
	}
	return &newOpts
}

type jsonInfo struct {
	ClientIP           string    `json:"client_ip,omitempty"`
	ClientName         string    `json:"client_name,omitempty"`
	Fingerprint        string    `json:"fingerprint"`
	HeaderSig          []byte    `json:"header_sig,omitempty"`
	Md5                string    `json:"md5"`
	Nevra              string    `json:"nevra"`
	PatchReplaceLength int       `json:"patch_replace_length,omitempty"`
	PayloadSig         []byte    `json:"payload_sig,omitempty"`
	Sha1               string    `json:"sha1"`
	Timestamp          time.Time `json:"timestamp"`
}

func (info *SigInfo) fillJinfo() *jsonInfo {
	jinfo := new(jsonInfo)
	jinfo.Fingerprint = info.Fingerprint
	nevra, _ := info.Header.GetNEVRA()
	snevra := nevra.String()
	jinfo.Nevra = snevra[:len(snevra)-4] // strip .rpm
	md5, _ := info.Header.GetBytes(rpmutils.SIG_MD5)
	jinfo.Md5 = fmt.Sprintf("%x", md5)
	jinfo.Sha1, _ = info.Header.GetString(rpmutils.SIG_SHA1)
	jinfo.Timestamp = info.Timestamp
	jinfo.ClientIP = info.ClientIP
	jinfo.ClientName = info.ClientName
	return jinfo
}

func (info *SigInfo) Dump(stream io.Writer) {
	jinfo := info.fillJinfo()
	jinfo.HeaderSig, _ = info.Header.GetBytes(rpmutils.SIG_RSA)
	jinfo.PayloadSig, _ = info.Header.GetBytes(rpmutils.SIG_PGP)

	enc := json.NewEncoder(stream)
	enc.SetIndent("", "  ")
	enc.Encode(&jinfo)
	stream.Write([]byte{'\n'})
}

func (info *SigInfo) DumpPatch(stream io.Writer) error {
	patch, err := info.Header.DumpSignatureHeader(true)
	if err != nil {
		return err
	}
	jinfo := info.fillJinfo()
	jinfo.PatchReplaceLength = info.Header.OriginalSignatureHeaderSize()
	enc := json.NewEncoder(stream)
	enc.Encode(&jinfo)
	stream.Write([]byte{0})
	stream.Write(patch)
	return nil
}

func (info *SigInfo) String() string {
	nevra, _ := info.Header.GetNEVRA()
	snevra := nevra.String()
	snevra = snevra[:len(snevra)-4] // strip .rpm
	md5, _ := info.Header.GetBytes(rpmutils.SIG_MD5)
	sha1, _ := info.Header.GetString(rpmutils.SIG_SHA1)
	ret := fmt.Sprintf("Signed RPM: nevra=%s key=%s fp=%s md5=%X sha1=%s", snevra, info.KeyName, info.Fingerprint, md5, sha1)
	if info.ClientIP != "" || info.ClientName != "" {
		ret += fmt.Sprintf(" client=%s ip=%s", info.ClientName, info.ClientIP)
	}
	return ret
}

func SignRpmStream(stream io.Reader, key *packet.PrivateKey, opts *rpmutils.SignatureOptions) (*SigInfo, error) {
	opts = defaultOpts(opts)
	header, err := rpmutils.SignRpmStream(stream, key, opts)
	if err != nil {
		return nil, err
	}
	fp := fmt.Sprintf("%X", key.PublicKey.Fingerprint)[:]
	return &SigInfo{Header: header, Fingerprint: fp, Timestamp: opts.CreationTime}, nil
}

func SignRpmFile(infile *os.File, outpath string, key *packet.PrivateKey, opts *rpmutils.SignatureOptions) (*SigInfo, error) {
	opts = defaultOpts(opts)
	header, err := rpmutils.SignRpmFile(infile, outpath, key, opts)
	if err != nil {
		return nil, err
	}
	fp := fmt.Sprintf("%X", key.PublicKey.Fingerprint)[:]
	return &SigInfo{Header: header, Fingerprint: fp, Timestamp: opts.CreationTime}, nil
}

func SignRpmFileWithJson(infile *os.File, outpath string, blob []byte) (*SigInfo, error) {
	var jinfo jsonInfo
	err := json.Unmarshal(blob, &jinfo)
	if err != nil {
		return nil, err
	}
	header, err := rpmutils.RewriteWithSignatures(infile, outpath, jinfo.PayloadSig, jinfo.HeaderSig)
	if err != nil {
		return nil, err
	}
	return &SigInfo{Header: header, Fingerprint: jinfo.Fingerprint, Timestamp: jinfo.Timestamp}, nil
}
