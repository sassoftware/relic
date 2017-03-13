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
	"fmt"
	"time"

	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/authenticode"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/binpatch"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/pkcs7"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/x509tools"
	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/zipslicer"
)

var (
	SpcUuidSipInfoAppx = []byte{0x4B, 0xDF, 0xC5, 0x0A, 0x07, 0xCE, 0xE2, 0x4D, 0xB7, 0x6E, 0x23, 0xC8, 0x39, 0xA0, 0x9F, 0xD1}
	appxSipInfo        = authenticode.SpcSipInfo{0x1010000, SpcUuidSipInfoAppx, 0, 0, 0, 0, 0}
)

// Sign a previously consumed appx tar, producing a appx signature tar
func (i *AppxDigest) Sign(privKey crypto.Signer, certs []*x509.Certificate) (*pkcs7.ContentInfoSignedData, error) {
	i.now = time.Now().UTC()
	// Update manifest
	if i.manifest != nil {
		i.manifest.SetPublisher(certs[0])
		manifest, err := i.manifest.Marshal()
		if err != nil {
			return nil, err
		}
		if err := i.addZipEntry(appxManifest, manifest); err != nil {
			return nil, err
		}
	} else if i.bundle != nil {
		i.bundle.SetPublisher(certs[0])
		manifest, err := i.bundle.Marshal()
		if err != nil {
			return nil, err
		}
		if err := i.addZipEntry(bundleManifestFile, manifest); err != nil {
			return nil, err
		}
	}
	// Update blockmap
	blockmap, err := i.blockMap.Marshal()
	if err != nil {
		return nil, err
	}
	if err := i.addZipEntry(appxBlockMap, blockmap); err != nil {
		return nil, err
	}
	d := i.Hash.New()
	d.Write(blockmap)
	i.axbm = d.Sum(nil)
	// Update content types
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
		return nil, err
	}
	if err := i.addZipEntry(appxContentTypes, ctypes); err != nil {
		return nil, err
	}
	d.Reset()
	d.Write(ctypes)
	i.axct = d.Sum(nil)
	// TODO: catalog
	if i.cattemp != nil {
		if err := i.addZipEntry(appxCodeIntegrity, i.cattemp); err != nil {
			return nil, err
		}
		d := i.Hash.New()
		d.Write(i.cattemp)
		i.axci = d.Sum(nil)
		fmt.Printf("%x\n", i.axci)
	}
	return i.makeSignature(privKey, certs)
}

func (i *AppxDigest) addZipEntry(name string, contents []byte) error {
	f, err := zipslicer.NewFile(i.outz, name, contents, &i.patchBuf)
	if err != nil {
		return err
	}
	return i.blockMap.AddFile(f, i.axpc, nil)
}

func (i *AppxDigest) makeSignature(privKey crypto.Signer, certs []*x509.Certificate) (*pkcs7.ContentInfoSignedData, error) {
	axcd := i.Hash.New()
	if err := i.outz.WriteDirectory(axcd); err != nil {
		return nil, err
	}
	alg, ok := x509tools.PkixDigestAlgorithm(i.Hash)
	if !ok {
		return nil, errors.New("unsupported digest algorithm")
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
	var indirect authenticode.SpcIndirectDataContentMsi
	indirect.Data.Type = authenticode.OidSpcSipInfo
	indirect.Data.Value = appxSipInfo
	indirect.MessageDigest.Digest = digest.Bytes()
	indirect.MessageDigest.DigestAlgorithm = alg
	sig := pkcs7.NewBuilder(privKey, certs, i.Hash)
	if err := sig.SetContent(authenticode.OidSpcIndirectDataContent, indirect); err != nil {
		return nil, err
	}
	if err := sig.AddAuthenticatedAttribute(authenticode.OidSpcSpOpusInfo, authenticode.SpcSpOpusInfo{}); err != nil {
		return nil, err
	}
	// TODO: statement type
	return sig.Sign()
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
	fmt.Println("PATCH", i.patchStart)
	return patch, nil
}
