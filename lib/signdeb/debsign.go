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

package signdeb

import (
	"bytes"
	"crypto"
	"fmt"
	"io"
	"strings"
	"time"

	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/binpatch"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/pgptools"

	"github.com/qur/ar"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
)

func Sign(r io.Reader, signer *openpgp.Entity, opts crypto.SignerOpts, role string) (*binpatch.PatchSet, error) {
	counter := &readCounter{r: r}
	now := time.Now().UTC()
	reader := ar.NewReader(counter)
	msg := new(bytes.Buffer)
	fmt.Fprintln(msg, "Version: 4")
	fmt.Fprintln(msg, "Signer:", pgptools.EntityName(signer))
	fmt.Fprintln(msg, "Date:", now.Format(time.ANSIC))
	fmt.Fprintln(msg, "Role:", role)
	fmt.Fprintln(msg, "Files: ")
	var patchOffset int64
	var patchLength uint32
	filename := "_gpg" + role
	for {
		hdr, err := reader.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
		if hdr.Name == filename {
			// mark the old signature for removal
			patchOffset = counter.n - 60
			patchLength = uint32(60 + ((hdr.Size+1)/2)*2)
		}
		if strings.HasPrefix(hdr.Name, "_gpg") {
			continue
		}
		md5 := crypto.MD5.New()
		sha1 := crypto.SHA1.New()
		if _, err := io.Copy(io.MultiWriter(md5, sha1), reader); err != nil {
			return nil, err
		}
		fmt.Fprintf(msg, "\t%x %x %d %s\n", md5.Sum(nil), sha1.Sum(nil), hdr.Size, hdr.Name)
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
		patchOffset = counter.n // end of file
	}
	patch := binpatch.New(map[string]interface{}{
		"fingerprint": signer.PrimaryKey.Fingerprint,
		"timestamp":   now.String(),
	})
	patch.Add(patchOffset, patchLength, pbuf.Bytes())
	return patch, nil
}

type readCounter struct {
	r io.Reader
	n int64
}

func (c *readCounter) Read(d []byte) (int, error) {
	n, err := c.r.Read(d)
	c.n += int64(n)
	return n, err
}
