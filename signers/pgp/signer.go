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
	"time"

	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/atomicfile"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/certloader"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/magic"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/pgptools"
	"gerrit-pdt.unx.sas.com/tools/relic.git/signers"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
)

var PgpSigner = &signers.Signer{
	Name:       "pgp",
	Magic:      magic.FileTypePGP,
	CertTypes:  signers.CertTypePgp,
	AllowStdin: true,
	Transform:  transform,
	Sign:       sign,
	Verify:     verify,
}

const maxStreamClearSignSize = 10 * 1000 * 1000

func init() {
	PgpSigner.Flags().BoolP("armor", "a", false, "(PGP) Create ASCII armored output")
	PgpSigner.Flags().Bool("clearsign", false, "(PGP) Create a cleartext signature")
	PgpSigner.Flags().BoolP("textmode", "t", false, "(PGP) Sign in CRLF canonical text form")
	// for compat with 2.0 clients
	PgpSigner.Flags().String("pgp", "", "")
	PgpSigner.Flags().MarkHidden("pgp")
	signers.Register(PgpSigner)
}

type pgpTransformer struct {
	clearsign bool
	size      int64
	stream    io.ReadSeeker
	closer    io.Closer
}

func transform(f *os.File, opts signers.SignOpts) (signers.Transformer, error) {
	clearsign, _ := opts.Flags.GetBool("clearsign")
	stream := io.ReadSeeker(f)
	size, err := stream.Seek(0, io.SeekEnd)
	if err != nil {
		// not seekable so consume it all now
		contents, err := ioutil.ReadAll(io.LimitReader(stream, maxStreamClearSignSize))
		if err != nil {
			return nil, err
		} else if len(contents) == maxStreamClearSignSize {
			return nil, errors.New("input stream is too big, try writing it to file first")
		}
		stream = bytes.NewReader(contents)
		size = int64(len(contents))
	}
	return &pgpTransformer{clearsign, size, stream, f}, nil
}

func (t *pgpTransformer) GetReader() (io.Reader, int64, error) {
	if _, err := t.stream.Seek(0, 0); err != nil {
		return nil, 0, err
	}
	return t.stream, t.size, nil
}

func sign(r io.Reader, cert *certloader.Certificate, opts signers.SignOpts) ([]byte, error) {
	armor, _ := opts.Flags.GetBool("armor")
	clearsign, _ := opts.Flags.GetBool("clearsign")
	textmode, _ := opts.Flags.GetBool("textmode")
	if pgpcompat, _ := opts.Flags.GetString("pgp"); pgpcompat == "mini-clear" {
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
	if t.clearsign {
		// reassemble cleartext signature
		if _, err := t.stream.Seek(0, 0); err != nil {
			return err
		}
		sig, err := ioutil.ReadAll(result)
		if err != nil {
			return err
		}
		if err := pgptools.MergeClearSign(outfile, sig, t.stream); err != nil {
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

func verify(f *os.File, opts signers.VerifyOpts) ([]*signers.Signature, error) {
	br := bufio.NewReader(f)
	// remove ASCII armor
	reader := io.Reader(br)
	if x, _ := br.Peek(34); len(x) >= 1 && x[0] == '-' {
		if bytes.HasPrefix(x, []byte("-----BEGIN PGP SIGNED MESSAGE-----")) {
			// clearsign
			sig, _, err := pgptools.VerifyClearSign(reader, opts.TrustedPgp)
			return verifyPgp(sig, f.Name(), err)
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
		return verifyPgp(sig, f.Name(), err)
	} else {
		// inline signature
		sig, _, err := pgptools.VerifyInline(reader, opts.TrustedPgp)
		return verifyPgp(sig, f.Name(), err)
	}
}

func verifyPgp(sig *pgptools.PgpSignature, name string, err error) ([]*signers.Signature, error) {
	if err == nil {
		return []*signers.Signature{&signers.Signature{
			CreationTime: sig.CreationTime,
			Hash:         sig.Hash,
			SignerPgp:    sig.Key.Entity,
		}}, nil
	} else if sig != nil {
		return nil, fmt.Errorf("bad signature from %s(%x) [%s]: %s", pgptools.EntityName(sig.Key.Entity), sig.Key.PublicKey.KeyId, sig.CreationTime, err)
	} else if _, ok := err.(pgptools.ErrNoKey); ok {
		return nil, fmt.Errorf("%s; use --cert to specify known keys", err)
	} else {
		return nil, err
	}
}
