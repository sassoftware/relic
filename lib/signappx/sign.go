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

package signappx

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"

	"github.com/sassoftware/relic/v7/lib/authenticode"
	"github.com/sassoftware/relic/v7/lib/binpatch"
	"github.com/sassoftware/relic/v7/lib/certloader"
	"github.com/sassoftware/relic/v7/lib/pkcs9"
)

var (
	SpcUUIDSipInfoAppx = []byte{0x4B, 0xDF, 0xC5, 0x0A, 0x07, 0xCE, 0xE2, 0x4D, 0xB7, 0x6E, 0x23, 0xC8, 0x39, 0xA0, 0x9F, 0xD1}
	appxSipInfo        = authenticode.SpcSipInfo{A: 0x1010000, UUID: SpcUUIDSipInfoAppx}
)

func (i *AppxDigest) Sign(ctx context.Context, cert *certloader.Certificate, params *authenticode.OpusParams) (patch *binpatch.PatchSet, priSig, catSig *pkcs9.TimestampedSignature, err error) {
	if err := i.writeManifest(cert.Leaf); err != nil {
		return nil, nil, nil, err
	}
	if err := i.writeBlockMap(); err != nil {
		return nil, nil, nil, err
	}
	if err := i.writeContentTypes(); err != nil {
		return nil, nil, nil, err
	}
	catSig, err = i.writeCodeIntegrity(ctx, cert, params)
	if err != nil {
		return nil, nil, nil, err
	}
	ts, err := i.writeSignature(ctx, cert, params)
	if err != nil {
		return nil, nil, nil, err
	}
	w := &i.patchBuf
	if err := i.outz.WriteDirectory(w, w, true); err != nil {
		return nil, nil, nil, err
	}
	patch = binpatch.New()
	patch.Add(i.patchStart, i.patchLen, i.patchBuf.Bytes())
	return patch, ts, catSig, nil
}

func (i *AppxDigest) addZipEntry(name string, contents []byte) error {
	// Don't deflate the manifest because I can't figure out how to correctly
	// calculate block sizes. The blocks for the rest of the files can be
	// cribbed from the old blockmap.
	deflate := !(name == appxManifest || name == bundleManifestFile)
	// Don't use descriptors for the 3 files that signtool adds, it seems to
	// aggrevate the generic verifier although the appx works fine.
	useDesc := !(name == appxContentTypes || name == appxCodeIntegrity || name == appxSignature)
	f, err := i.outz.NewFile(name, nil, contents, &i.patchBuf, i.mtime, deflate, useDesc)
	if err != nil {
		return err
	}
	return i.blockMap.AddFile(f, i.axpc, nil)
}

func (i *AppxDigest) writeManifest(leaf *x509.Certificate) error {
	if i.manifest != nil {
		i.manifest.SetPublisher(leaf)
		manifest, err := i.manifest.Marshal()
		if err != nil {
			return err
		}
		return i.addZipEntry(appxManifest, manifest)
	} else if i.bundle != nil {
		i.bundle.SetPublisher(leaf)
		manifest, err := i.bundle.Marshal()
		if err != nil {
			return err
		}
		return i.addZipEntry(bundleManifestFile, manifest)
	}
	return errors.New("manifest not found")
}

func (i *AppxDigest) writeBlockMap() error {
	blockmap, err := i.blockMap.Marshal()
	if err != nil {
		return err
	}
	if err := i.addZipEntry(appxBlockMap, blockmap); err != nil {
		return err
	}
	d := i.Hash.New()
	d.Write(blockmap)
	i.axbm = d.Sum(nil)
	return nil
}

func (i *AppxDigest) writeContentTypes() error {
	for _, f := range i.outz.File {
		if f.Name != appxContentTypes {
			i.contentTypes.Add(f.Name)
		}
	}
	if len(i.peDigests) != 0 {
		i.contentTypes.Add(appxCodeIntegrity)
	}
	i.contentTypes.Add(appxSignature)
	ctypes, err := i.contentTypes.Marshal()
	if err != nil {
		return err
	}
	if err := i.addZipEntry(appxContentTypes, ctypes); err != nil {
		return err
	}
	d := i.Hash.New()
	d.Write(ctypes)
	i.axct = d.Sum(nil)
	return nil
}

func (i *AppxDigest) writeCodeIntegrity(ctx context.Context, cert *certloader.Certificate, params *authenticode.OpusParams) (*pkcs9.TimestampedSignature, error) {
	if len(i.peDigests) == 0 {
		return nil, nil
	}
	cat := authenticode.NewCatalog(i.Hash)
	for _, d := range i.peDigests {
		indirect, err := d.GetIndirect()
		if err != nil {
			return nil, err
		}
		if err := cat.Add(indirect); err != nil {
			return nil, err
		}
	}
	ts, err := cat.Sign(ctx, cert, params)
	if err != nil {
		return nil, err
	}
	catalog := ts.Raw
	if err := i.addZipEntry(appxCodeIntegrity, catalog); err != nil {
		return nil, err
	}
	d := i.Hash.New()
	d.Write(catalog)
	i.axci = d.Sum(nil)
	return ts, nil
}

func (i *AppxDigest) writeSignature(ctx context.Context, cert *certloader.Certificate, params *authenticode.OpusParams) (*pkcs9.TimestampedSignature, error) {
	axcd := i.Hash.New()
	if err := i.outz.WriteDirectory(axcd, axcd, true); err != nil {
		return nil, err
	}
	digest := bytes.NewBuffer(make([]byte, 0, 4+5*(4+i.Hash.Size())))
	digest.WriteString("APPX")
	digest.WriteString("AXPC")
	digest.Write(i.axpc.Sum(nil))
	digest.WriteString("AXCD")
	digest.Write(axcd.Sum(nil))
	digest.WriteString("AXCT")
	digest.Write(i.axct)
	digest.WriteString("AXBM")
	digest.Write(i.axbm)
	if len(i.axci) != 0 {
		digest.WriteString("AXCI")
		digest.Write(i.axci)
	}
	ts, err := authenticode.SignSip(ctx, digest.Bytes(), i.Hash, appxSipInfo, cert, params)
	if err != nil {
		return nil, err
	}
	pkcx := make([]byte, 4, 4+len(ts.Raw))
	copy(pkcx, "PKCX")
	pkcx = append(pkcx, ts.Raw...)
	if err := i.addZipEntry(appxSignature, pkcx); err != nil {
		return nil, err
	}
	return ts, nil
}
