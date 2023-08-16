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
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"golang.org/x/crypto/openpgp"

	"github.com/sassoftware/relic/v7/lib/audit"
	"github.com/sassoftware/relic/v7/lib/certloader"
	"github.com/sassoftware/relic/v7/lib/magic"
	"github.com/sassoftware/relic/v7/lib/pgptools"
	"github.com/sassoftware/relic/v7/lib/pkcs9"
	"github.com/sassoftware/relic/v7/lib/x509tools"
	"github.com/sassoftware/relic/v7/signers/sigerrors"
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
	FormatLog func(*audit.Info) *zerolog.Event
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
func MergeFlags(cmd *cobra.Command) {
	if flagMap == nil {
		flagMap = make(map[string][]string)
	}
	fs := cmd.Flags()
	fs.AddFlagSet(common)
	for _, s := range registered {
		if s.flags == nil {
			continue
		}
		fs.AddFlagSet(s.flags)
		s.flags.VisitAll(func(flag *pflag.Flag) {
			flagMap[flag.Name] = append(flagMap[flag.Name], s.Name)
		})
	}
	// customize the usage function so that if --sig-type is set then only those flags are displayed
	orig := cmd.UsageFunc()
	cmd.SetUsageFunc(func(c *cobra.Command) error {
		if t, _ := fs.GetString("sig-type"); t != "" {
			for name, signers := range flagMap {
				var ok bool
				for _, signer := range signers {
					if signer == t {
						ok = true
						break
					}
				}
				if !ok {
					_ = fs.MarkHidden(name)
				}
			}
		}
		return orig(c)
	})
}

// IsSigned checks if a file contains a signature
func (s *Signer) IsSigned(f *os.File) (bool, error) {
	var err error
	if s.VerifyStream != nil {
		_, err = s.VerifyStream(f, VerifyOpts{NoDigests: true, NoChain: true})
	} else if s.Verify != nil {
		_, err = s.Verify(f, VerifyOpts{NoDigests: true, NoChain: true})
	} else {
		return false, errors.New("cannot check if this type of file is signed")
	}
	if err == nil {
		return true, nil
	}
	switch err.(type) {
	case sigerrors.NotSignedError:
		return false, nil
	case pgptools.ErrNoKey:
		return true, nil
	}
	return false, err
}
