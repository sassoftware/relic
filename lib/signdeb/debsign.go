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

package signdeb

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"path"
	"strings"
	"time"

	"github.com/sassoftware/relic/v7/lib/binpatch"
	"github.com/sassoftware/relic/v7/lib/pgptools"
	"github.com/sassoftware/relic/v7/lib/readercounter"

	"github.com/qur/ar"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
)

type DebSignature struct {
	Info         PackageInfo
	CreationTime time.Time
	PatchSet     *binpatch.PatchSet
}

// Sign a .deb file with the given PGP key. A role name is needed for the
// signature, e.g. "builder". Returns a structure holding a PatchSet that can
// be applied to the original file to add or replace the signature.
func Sign(r io.Reader, signer *openpgp.Entity, opts crypto.SignerOpts, role string) (*DebSignature, error) {
	counter := readercounter.New(r)
	now := time.Now().UTC()
	reader := ar.NewReader(counter)
	msg := new(bytes.Buffer)
	fmt.Fprintln(msg, "Version: 4")
	fmt.Fprintln(msg, "Signer:", pgptools.EntityName(signer))
	fmt.Fprintln(msg, "Date:", now.Format(time.ANSIC))
	fmt.Fprintln(msg, "Role:", role)
	fmt.Fprintln(msg, "Files: ")
	var patchOffset, patchLength int64
	var info *PackageInfo
	filename := "_gpg" + role
	for {
		hdr, err := reader.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
		name := path.Clean(hdr.Name)
		if name == filename {
			// mark the old signature for removal
			patchOffset = counter.N - 60
			patchLength = int64(60 + ((hdr.Size+1)/2)*2)
		}
		if strings.HasPrefix(name, "_gpg") {
			continue
		}
		save := io.Writer(ioutil.Discard)
		var closer io.Closer
		var infoch chan *PackageInfo
		var errch chan error
		if strings.HasPrefix(name, "control.tar") {
			// use a goroutine pipe to parse the control tarball as it's digested
			ext := name[11:]
			r, w := io.Pipe()
			save = w
			closer = w
			infoch = make(chan *PackageInfo, 1)
			errch = make(chan error, 1)
			go func() {
				info, err := parseControl(r, ext)
				// ensure whole file is read, otherwise pipe will stall
				_, _ = io.Copy(ioutil.Discard, r)
				infoch <- info
				errch <- err
			}()
		}
		md5 := crypto.MD5.New()
		sha1 := crypto.SHA1.New()
		if _, err := io.Copy(io.MultiWriter(md5, sha1, save), reader); err != nil {
			return nil, err
		}
		if closer != nil {
			closer.Close()
		}
		fmt.Fprintf(msg, "\t%x %x %d %s\n", md5.Sum(nil), sha1.Sum(nil), hdr.Size, hdr.Name)
		if errch != nil {
			// retrieve the result of parsing the control file
			info = <-infoch
			if err := <-errch; err != nil {
				return nil, err
			}
		}
	}
	if info == nil {
		return nil, errors.New("deb has no control.tar")
	}
	fmt.Fprintln(msg)
	signed := new(bytes.Buffer)
	config := &packet.Config{
		DefaultHash: opts.HashFunc(),
		Time:        func() time.Time { return now },
	}
	if err := pgptools.ClearSign(signed, signer, msg, config); err != nil {
		return nil, err
	}
	// Format as an ar fragment and turn it into a binpatch that will update
	// the original archive
	pbuf := new(bytes.Buffer)
	writer := ar.NewWriter(pbuf)
	hdr := &ar.Header{
		Name:    filename,
		Size:    int64(signed.Len()),
		ModTime: now,
		Mode:    0100644,
	}
	if err := writer.WriteHeader(hdr); err != nil {
		return nil, err
	}
	if _, err := writer.Write(signed.Bytes()); err != nil {
		return nil, err
	}
	if patchOffset == 0 {
		patchOffset = counter.N // end of file
	}
	patch := binpatch.New()
	patch.Add(patchOffset, patchLength, pbuf.Bytes())
	return &DebSignature{*info, now, patch}, nil
}
