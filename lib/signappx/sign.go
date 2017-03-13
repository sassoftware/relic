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

package signappx

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"errors"
	"time"

	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/authenticode"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/binpatch"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/pkcs7"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/zipslicer"
)

var (
	SpcUuidSipInfoAppx = []byte{0x4B, 0xDF, 0xC5, 0x0A, 0x07, 0xCE, 0xE2, 0x4D, 0xB7, 0x6E, 0x23, 0xC8, 0x39, 0xA0, 0x9F, 0xD1}
	appxSipInfo        = authenticode.SpcSipInfo{0x1010000, SpcUuidSipInfoAppx, 0, 0, 0, 0, 0}
)

func (i *AppxDigest) SignCatalog(privKey crypto.Signer, certs []*x509.Certificate) (*pkcs7.ContentInfoSignedData, error) {
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
	return cat.Sign(privKey, certs)
}

// Sign a previously consumed appx tar, producing a appx signature tar
func (i *AppxDigest) Sign(catalog []byte, privKey crypto.Signer, certs []*x509.Certificate) (*pkcs7.ContentInfoSignedData, error) {
	i.now = time.Now().UTC()
	if err := i.writeManifest(certs[0]); err != nil {
		return nil, err
	}
	if err := i.writeBlockMap(); err != nil {
		return nil, err
	}
	if err := i.writeContentTypes(); err != nil {
		return nil, err
	}
	if err := i.writeCodeIntegrity(catalog); err != nil {
		return nil, err
	}
	return i.writeSignature(privKey, certs)
}

func (i *AppxDigest) addZipEntry(name string, contents []byte) error {
	f, err := zipslicer.NewFile(i.outz, name, contents, &i.patchBuf)
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

func (i *AppxDigest) writeCodeIntegrity(catalog []byte) error {
	if len(catalog) == 0 {
		return nil
	}
	if err := i.addZipEntry(appxCodeIntegrity, catalog); err != nil {
		return err
	}
	d := i.Hash.New()
	d.Write(catalog)
	i.axci = d.Sum(nil)
	return nil
}

func (i *AppxDigest) writeSignature(privKey crypto.Signer, certs []*x509.Certificate) (*pkcs7.ContentInfoSignedData, error) {
	axcd := i.Hash.New()
	if err := i.outz.WriteDirectory(axcd); err != nil {
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
	return authenticode.SignSip(digest.Bytes(), i.Hash, appxSipInfo, privKey, certs)
}

func (i *AppxDigest) MakePatch(pkcs []byte) (*binpatch.PatchSet, error) {
	pkcx := make([]byte, 4, 4+len(pkcs))
	copy(pkcx, "PKCX")
	pkcx = append(pkcx, pkcs...)
	if err := i.addZipEntry(appxSignature, pkcx); err != nil {
		return nil, err
	}
	if err := i.outz.WriteDirectory(&i.patchBuf); err != nil {
		return nil, err
	}
	patch := binpatch.New()
	patch.Add(i.patchStart, uint32(i.patchLen), i.patchBuf.Bytes())
	return patch, nil
}
