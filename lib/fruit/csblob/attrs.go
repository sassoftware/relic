package csblob

import (
	"crypto"
	"crypto/hmac"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"

	"howett.net/plist"

	"github.com/sassoftware/relic/v7/lib/pkcs7"
	"github.com/sassoftware/relic/v7/lib/x509tools"
)

func checkCDHashes(si *pkcs7.SignerInfo, computed map[crypto.Hash][]byte) error {
	var cdHashes []cdHashAttrib
	if err := si.AuthenticatedAttributes.GetAll(AttrCodeDirHashes, &cdHashes); err != nil {
		if _, ok := err.(pkcs7.ErrNoAttribute); ok {
			return nil
		}
		return err
	}
	for _, cd := range cdHashes {
		hash, err := x509tools.PkixDigestToHashE(pkix.AlgorithmIdentifier{Algorithm: cd.Algorithm})
		if err != nil {
			return err
		}
		hc := computed[hash]
		if hc == nil {
			return fmt.Errorf("missing hash with algorithm %s", hash)
		}
		if !hmac.Equal(hc, cd.Digest) {
			return fmt.Errorf("digest mismatch: expected %x, got %x", cd.Digest, hc)
		}
	}
	return nil
}

func addCSHashes(builder *pkcs7.SignatureBuilder, hashes []cdHashAttrib) error {
	for _, h := range hashes {
		if err := builder.AddAuthenticatedAttribute(AttrCodeDirHashes, h); err != nil {
			return err
		}
	}
	return nil
}

func checkPlistHashes(dirs []*CodeDirectory, si *pkcs7.SignerInfo, computed map[crypto.Hash][]byte) error {
	var computedList [][]byte
	for _, dir := range dirs {
		computedList = append(computedList, computed[dir.HashFunc][:20])
	}
	var plistText []byte
	if err := si.AuthenticatedAttributes.GetOne(AttrCodeDirHashPlist, &plistText); err != nil {
		if _, ok := err.(pkcs7.ErrNoAttribute); ok {
			return nil
		}
		return err
	}
	var parsed cdHashPlist
	if _, err := plist.Unmarshal(plistText, &parsed); err != nil {
		return err
	}
	if len(parsed.CDHashes) != len(computedList) {
		return fmt.Errorf("expected %d hashes but got %d", len(parsed.CDHashes), len(computedList))
	}
	for i, expected := range parsed.CDHashes {
		actual := computedList[i]
		if !hmac.Equal(expected, actual) {
			return fmt.Errorf("digest mismatch: expected %x, got %x", expected, actual)
		}
	}
	return nil
}

func addPlistHashes(builder *pkcs7.SignatureBuilder, pl cdHashPlist) error {
	blob, err := plist.MarshalIndent(pl, plist.XMLFormat, "  ")
	if err != nil {
		return err
	}
	return builder.AddAuthenticatedAttribute(AttrCodeDirHashPlist, blob)
}

type cdHashAttrib struct {
	Algorithm asn1.ObjectIdentifier
	Digest    []byte
}

type cdHashPlist struct {
	CDHashes [][]byte `plist:"cdhashes"`
}
