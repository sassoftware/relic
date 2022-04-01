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

package pgp

// Sign arbitrary data using PGP detached or cleartext signatures

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"

	"github.com/sassoftware/relic/v7/lib/atomicfile"
	"github.com/sassoftware/relic/v7/lib/certloader"
	"github.com/sassoftware/relic/v7/lib/magic"
	"github.com/sassoftware/relic/v7/lib/pgptools"
	"github.com/sassoftware/relic/v7/signers"
)

var PgpSigner = &signers.Signer{
	Name:         "pgp",
	Magic:        magic.FileTypePGP,
	CertTypes:    signers.CertTypePgp,
	AllowStdin:   true,
	Transform:    transform,
	Sign:         sign,
	VerifyStream: verify,
}

const maxStreamClearSignSize = 10 * 1000 * 1000

func init() {
	PgpSigner.Flags().BoolP("armor", "a", false, "(PGP) Create ASCII armored output")
	PgpSigner.Flags().Bool("inline", false, "(PGP) Create a signed message instead of a detached signature")
	PgpSigner.Flags().Bool("clearsign", false, "(PGP) Create a cleartext signature")
	PgpSigner.Flags().BoolP("textmode", "t", false, "(PGP) Sign in CRLF canonical text form")
	// for compat with 2.0 clients
	PgpSigner.Flags().String("pgp", "", "")
	_ = PgpSigner.Flags().MarkHidden("pgp")
	signers.Register(PgpSigner)
}

type pgpTransformer struct {
	inline, clearsign, armor bool

	filename string
	stream   io.ReadSeeker
	closer   io.Closer
}

func transform(f *os.File, opts signers.SignOpts) (signers.Transformer, error) {
	armor := opts.Flags.GetBool("armor")
	inline := opts.Flags.GetBool("inline")
	if inline {
		// always get a non-armored sig from the server
		opts.Flags.Values["armor"] = "false"
	}
	clearsign := opts.Flags.GetBool("clearsign")
	stream := io.ReadSeeker(f)
	if _, err := f.Seek(0, 0); err != nil {
		// not seekable so consume it all now
		contents, err := ioutil.ReadAll(io.LimitReader(stream, maxStreamClearSignSize))
		if err != nil {
			return nil, err
		} else if len(contents) == maxStreamClearSignSize {
			return nil, errors.New("input stream is too big, try writing it to file first")
		}
		stream = bytes.NewReader(contents)
	}
	return &pgpTransformer{
		inline:    inline,
		clearsign: clearsign,
		armor:     armor,
		filename:  filepath.Base(f.Name()),
		stream:    stream,
		closer:    f,
	}, nil
}

func (t *pgpTransformer) GetReader() (io.Reader, error) {
	if _, err := t.stream.Seek(0, 0); err != nil {
		return nil, err
	}
	return t.stream, nil
}

func sign(r io.Reader, cert *certloader.Certificate, opts signers.SignOpts) ([]byte, error) {
	armor := opts.Flags.GetBool("armor")
	clearsign := opts.Flags.GetBool("clearsign")
	textmode := opts.Flags.GetBool("textmode")
	if pgpcompat := opts.Flags.GetString("pgp"); pgpcompat == "mini-clear" {
		clearsign = true
	}
	var sf func(io.Writer, *openpgp.Entity, io.Reader, *packet.Config) error
	if clearsign {
		sf = pgptools.DetachClearSign
	} else if armor {
		if textmode {
			sf = openpgp.ArmoredDetachSignText
		} else {
			sf = openpgp.ArmoredDetachSign
		}
	} else {
		if textmode {
			sf = openpgp.DetachSignText
		} else {
			sf = openpgp.DetachSign
		}
	}
	var buf bytes.Buffer
	config := &packet.Config{
		DefaultHash: opts.Hash,
		Time:        func() time.Time { return opts.Time },
	}
	if err := sf(&buf, cert.PgpKey, r, config); err != nil {
		return nil, err
	} else if armor {
		buf.WriteByte('\n')
	}
	return buf.Bytes(), nil
}

func (t *pgpTransformer) Apply(dest, mimeType string, result io.Reader) error {
	outfile, err := atomicfile.WriteAny(dest)
	if err != nil {
		return err
	}
	defer outfile.Close()
	if t.inline || t.clearsign {
		// reassemble signature
		if _, err := t.stream.Seek(0, 0); err != nil {
			return err
		}
		sig, err := ioutil.ReadAll(result)
		if err != nil {
			return err
		}
		if t.clearsign {
			err = pgptools.MergeClearSign(outfile, sig, t.stream)
		} else {
			err = pgptools.MergeSignature(outfile, sig, t.stream, t.armor, t.filename)
		}
		if err != nil {
			return err
		}
	} else {
		if _, err := io.Copy(outfile, result); err != nil {
			return err
		}
	}
	t.closer.Close()
	return outfile.Commit()
}

func verify(r io.Reader, opts signers.VerifyOpts) ([]*signers.Signature, error) {
	br := bufio.NewReader(r)
	// remove ASCII armor
	reader := io.Reader(br)
	if x, _ := br.Peek(34); len(x) >= 1 && x[0] == '-' {
		if bytes.HasPrefix(x, []byte("-----BEGIN PGP SIGNED MESSAGE-----")) {
			// clearsign
			sig, err := pgptools.VerifyClearSign(reader, nil, opts.TrustedPgp)
			return verifyPgp(sig, opts.FileName, err)
		}
		block, err := armor.Decode(reader)
		if err != nil {
			return nil, err
		}
		reader = block.Body
	}
	if opts.Content != "" {
		// detached signature
		fc, err := os.Open(opts.Content)
		if err != nil {
			return nil, err
		}
		defer fc.Close()
		sig, err := pgptools.VerifyDetached(reader, fc, opts.TrustedPgp)
		return verifyPgp(sig, opts.FileName, err)
	}
	// inline signature
	sig, err := pgptools.VerifyInline(reader, nil, opts.TrustedPgp)
	return verifyPgp(sig, opts.FileName, err)
}

func verifyPgp(sig *pgptools.PgpSignature, name string, err error) ([]*signers.Signature, error) {
	if err == nil {
		return []*signers.Signature{{
			CreationTime: sig.CreationTime,
			Hash:         sig.Hash,
			SignerPgp:    sig.Key.Entity,
		}}, nil
	} else if sig != nil {
		return nil, fmt.Errorf("bad signature from %s(%x) [%s]: %w", pgptools.EntityName(sig.Key.Entity), sig.Key.PublicKey.KeyId, sig.CreationTime, err)
	}
	return nil, err
}
