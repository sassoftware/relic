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

package signers

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/spf13/pflag"

	"github.com/sassoftware/relic/config"
	"github.com/sassoftware/relic/lib/audit"
	"github.com/sassoftware/relic/lib/binpatch"
	"github.com/sassoftware/relic/lib/certloader"
	"github.com/sassoftware/relic/lib/magic"
	"github.com/sassoftware/relic/lib/pgptools"
	"github.com/sassoftware/relic/lib/pkcs7"
	"github.com/sassoftware/relic/lib/pkcs9"
	"github.com/sassoftware/relic/lib/x509tools"
	"golang.org/x/crypto/openpgp"
)

type Signer struct {
	Name       string
	Aliases    []string
	Magic      magic.FileType
	CertTypes  CertType
	AllowStdin bool
	// Return true if the given filename is associated with this signer
	TestPath func(string) bool
	// Format audit attributes for logfile
	FormatLog func(*audit.Info) string
	// Verify a file, returning the set of signatures found. Performs integrity
	// checks but does not build X509 chains.
	Verify func(*os.File, VerifyOpts) ([]*Signature, error)
	// VerifyStream is like Verify but doesn't need to seek.
	VerifyStream func(io.Reader, VerifyOpts) ([]*Signature, error)
	// Transform a file into a stream to upload
	Transform func(*os.File, SignOpts) (Transformer, error)
	// Sign a input stream (possibly transformed) and return a mode-specific result blob
	Sign func(io.Reader, *certloader.Certificate, SignOpts) ([]byte, error)
	// Final step to run on the client after the file is patched
	Fixup func(*os.File) error

	flags *pflag.FlagSet
}

type CertType uint

const (
	CertTypeX509 CertType = 1 << iota
	CertTypePgp
)

type SignOpts struct {
	Path            string
	Hash            crypto.Hash
	Time            time.Time
	Flags           *pflag.FlagSet
	FlagOverride    map[string]string
	Audit           *audit.Info
	TimestampConfig *config.TimestampConfig
}

// Convenience method to return a binary patch
func (o SignOpts) SetBinPatch(p *binpatch.PatchSet) ([]byte, error) {
	o.Audit.SetMimeType(binpatch.MimeType)
	return p.Dump(), nil
}

// Convenience method to return a PKCS#7 blob
func (o SignOpts) SetPkcs7(ts *pkcs9.TimestampedSignature) ([]byte, error) {
	o.Audit.SetCounterSignature(ts.CounterSignature)
	o.Audit.SetMimeType(pkcs7.MimeType)
	return ts.Raw, nil
}

type VerifyOpts struct {
	FileName    string
	TrustedX509 []*x509.Certificate
	TrustedPgp  openpgp.EntityList
	TrustedPool *x509.CertPool
	NoDigests   bool
	NoChain     bool
	Content     string
	Compression magic.CompressionType
}

type Signature struct {
	Package       string
	SigInfo       string
	CreationTime  time.Time
	Hash          crypto.Hash
	Signer        string
	SignerPgp     *openpgp.Entity
	X509Signature *pkcs9.TimestampedSignature
}

func (s *Signature) SignerName() string {
	if s.Signer != "" {
		return s.Signer
	}
	if s.X509Signature != nil {
		return fmt.Sprintf("`%s`", x509tools.FormatSubject(s.X509Signature.Certificate))
	}
	if s.SignerPgp != nil {
		return fmt.Sprintf("`%s`(%x)", pgptools.EntityName(s.SignerPgp), s.SignerPgp.PrimaryKey.KeyId)
	}
	return "UNKNOWN"
}

var registered []*Signer
var flagMap map[string][]string

func Register(s *Signer) {
	registered = append(registered, s)
}

// Return the signer module with the given name or alias
func ByName(name string) *Signer {
	for _, s := range registered {
		if s.Name == name {
			return s
		}
		for _, n2 := range s.Aliases {
			if n2 == name {
				return s
			}
		}
	}
	return nil
}

// Return the signer module responsible for the given file magic
func ByMagic(m magic.FileType) *Signer {
	if m == magic.FileTypeUnknown {
		return nil
	}
	for _, s := range registered {
		if s.Magic == m {
			return s
		}
	}
	return nil
}

// Return the signer associated with the given filename extension
func ByFileName(name string) *Signer {
	for _, s := range registered {
		if s.TestPath != nil && s.TestPath(name) {
			return s
		}
	}
	return nil
}

// Return the named signer module if given, otherwise identify the file at the
// given path by contents or extension
func ByFile(name, sigtype string) (*Signer, error) {
	if sigtype != "" {
		mod := ByName(sigtype)
		if mod == nil {
			return nil, errors.New("no signer with that name")
		}
		return mod, nil
	}
	if name == "-" {
		return nil, errors.New("reading from standard input is not supported")
	}
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fileType, compressionType := magic.DetectCompressed(f)
	if compressionType != magic.CompressedNone {
		return nil, errors.New("cannot sign compressed file")
	}
	if mod := ByMagic(fileType); mod != nil {
		return mod, nil
	} else if mod := ByFileName(name); mod != nil {
		return mod, nil
	}
	return nil, errors.New("unknown filetype")
}

// Create a FlagSet for flags associated with this module. These will be added
// to "sign" and "remote sign", and transferred to a remote server via the URL
// query parameters.
func (s *Signer) Flags() *pflag.FlagSet {
	if s.flags == nil {
		s.flags = pflag.NewFlagSet(s.Name, pflag.ExitOnError)
	}
	return s.flags
}

// Add this module's flags to a command FlagSet
func MergeFlags(fs *pflag.FlagSet) {
	if flagMap == nil {
		flagMap = make(map[string][]string)
	}
	for _, s := range registered {
		if s.flags == nil {
			continue
		}
		fs.AddFlagSet(s.flags)
		s.flags.VisitAll(func(flag *pflag.Flag) {
			flagMap[flag.Name] = append(flagMap[flag.Name], s.Name)
		})
	}
}

type FlagValues map[string]pflag.Value

// Copy values back from the command to the module's own FlagSet
func (s *Signer) GetFlags(fs *pflag.FlagSet) (*pflag.FlagSet, error) {
	for flag, users := range flagMap {
		if !fs.Changed(flag) {
			continue
		}
		allowed := false
		for _, name := range users {
			if name == s.Name {
				allowed = true
				break
			}
		}
		if !allowed {
			return nil, fmt.Errorf("flag \"%s\" is not allowed for signature type \"%s\"", flag, s.Name)
		}
	}
	if s.flags == nil {
		return nil, nil
	}
	s.flags.VisitAll(func(flag *pflag.Flag) {
		if fs.Changed(flag.Name) {
			flag.Value = fs.Lookup(flag.Name).Value
		}
	})
	return s.flags, nil
}

// Copy module values to URL query parameters
func (s *Signer) FlagsToQuery(fs *pflag.FlagSet, override map[string]string, q url.Values) error {
	if s.flags == nil {
		return nil
	}
	fs, err := s.GetFlags(fs)
	if err != nil {
		return err
	}
	s.flags.VisitAll(func(flag *pflag.Flag) {
		if value, ok := override[flag.Name]; ok {
			q.Set(flag.Name, value)
		} else if fs.Changed(flag.Name) {
			q.Set(flag.Name, fs.Lookup(flag.Name).Value.String())
		}
	})
	return nil
}

// Copy URL query parameters to a set of command-line arguments to pass to an
// invocation of a child process
func (s *Signer) QueryToCmdline(q url.Values) []string {
	if s.flags == nil {
		return nil
	}
	var ret []string
	s.flags.VisitAll(func(flag *pflag.Flag) {
		v := q.Get(flag.Name)
		if v == "" {
			return
		}
		if flag.Value.Type() == "bool" {
			if bv, _ := strconv.ParseBool(v); bv {
				ret = append(ret, "--"+flag.Name)
			}
		} else {
			ret = append(ret, "--"+flag.Name, v)
		}
	})
	return ret
}
