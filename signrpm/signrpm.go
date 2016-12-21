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
	ClientIP    string    `json:"client_ip,omitempty"`
	ClientName  string    `json:"client_name,omitempty"`
	Fingerprint string    `json:"fingerprint"`
	HeaderSig   []byte    `json:"header_sig"`
	Md5         string    `json:"md5"`
	Nevra       string    `json:"nevra"`
	PayloadSig  []byte    `json:"payload_sig"`
	Sha1        string    `json:"sha1"`
	Timestamp   time.Time `json:"timestamp"`
}

func (info *SigInfo) Dump(stream io.Writer) {
	var jinfo jsonInfo
	jinfo.HeaderSig, _ = info.Header.GetBytes(rpmutils.SIG_RSA)
	jinfo.PayloadSig, _ = info.Header.GetBytes(rpmutils.SIG_PGP)
	jinfo.Fingerprint = info.Fingerprint
	nevra, _ := info.Header.GetNEVRA()
	jinfo.Nevra = nevra.String()
	md5, _ := info.Header.GetBytes(rpmutils.SIG_MD5)
	jinfo.Md5 = fmt.Sprintf("%x", md5)
	jinfo.Sha1, _ = info.Header.GetString(rpmutils.SIG_SHA1)
	jinfo.Timestamp = info.Timestamp
	jinfo.ClientIP = info.ClientIP
	jinfo.ClientName = info.ClientName

	enc := json.NewEncoder(stream)
	enc.SetIndent("", "  ")
	enc.Encode(&jinfo)
	stream.Write([]byte{'\n'})
}

func (info *SigInfo) String() string {
	nevra, _ := info.Header.GetNEVRA()
	md5, _ := info.Header.GetBytes(rpmutils.SIG_MD5)
	sha1, _ := info.Header.GetString(rpmutils.SIG_SHA1)
	ret := fmt.Sprintf("Signed RPM: nevra=%s key=%s fp=%s md5=%X sha1=%s", nevra, info.KeyName, info.Fingerprint, md5, sha1)
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
