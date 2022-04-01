package csblob

import (
	"crypto"
	"crypto/hmac"
	"errors"
	"fmt"
	"hash"
	"io"

	"github.com/sassoftware/relic/v7/lib/pkcs9"
)

type VerifiedBlob struct {
	Blob      *SigBlob
	Signature *pkcs9.TimestampedSignature
	HashFunc  crypto.Hash
}

type VerifyParams struct {
	InfoPlist   []byte
	Resources   []byte
	RepSpecific []byte
}

func Verify(blob []byte, params VerifyParams) (*VerifiedBlob, error) {
	sig, err := parseSignature(blob)
	if err != nil {
		return nil, err
	}
	// verify hashes in each code directory
	computedHashes := make(map[crypto.Hash][]byte)
	var hashFunc crypto.Hash
	for _, dir := range sig.Directories {
		hashFunc = dir.HashFunc
		h := dir.HashFunc.New()
		h.Write(dir.Raw)
		computedHashes[dir.HashFunc] = h.Sum(nil)
		if dir.EntitlementsDERHash != nil {
			if err := hashCheck(h, sig.EntitlementDER, dir.EntitlementsDERHash); err != nil {
				return nil, fmt.Errorf("entitlementsDER: %w", err)
			}
		}
		if dir.EntitlementsHash != nil {
			if err := hashCheck(h, sig.Entitlement, dir.EntitlementsHash); err != nil {
				return nil, fmt.Errorf("entitlements: %w", err)
			}
		}
		if dir.RequirementsHash != nil {
			if err := hashCheck(h, sig.RawRequirements, dir.RequirementsHash); err != nil {
				return nil, fmt.Errorf("requirements: %w", err)
			}
		}
		if dir.RepSpecificHash != nil {
			if err := hashCheck(h, params.RepSpecific, dir.RepSpecificHash); err != nil {
				return nil, fmt.Errorf("rep_specific: %w", err)
			}
		}
		if dir.ManifestHash != nil && params.InfoPlist != nil {
			if err := hashCheck(h, params.InfoPlist, dir.ManifestHash); err != nil {
				return nil, fmt.Errorf("info_plist: %w", err)
			}
		}
		if dir.ResourcesHash != nil && params.Resources != nil {
			if err := hashCheck(h, params.Resources, dir.ResourcesHash); err != nil {
				return nil, fmt.Errorf("resources: %w", err)
			}
		}
	}
	// verify CMS signature against the first code dir
	mdContent := sig.Directories[0].Raw
	if sig.CMS == nil {
		return nil, errors.New("signature wrapper not found, possibly an adhoc signature")
	}
	pksig, err := sig.CMS.Content.Verify(mdContent, false)
	if err != nil {
		return nil, err
	}
	// verify all code dirs using a propretiary attribute if present
	if err := checkCDHashes(pksig.SignerInfo, computedHashes); err != nil {
		return nil, fmt.Errorf("verifying cd hashes: %w", err)
	}
	// verify using plist attribute if present -- unnecessary but useful for documentation
	if err := checkPlistHashes(sig.Directories, pksig.SignerInfo, computedHashes); err != nil {
		return nil, fmt.Errorf("verifying cd hashes: plist: %w", err)
	}
	// mark proprietary certificate extensions as handled so it doesn't fail the chain
	for _, cert := range pksig.Intermediates {
		MarkHandledExtensions(cert)
	}
	// validate timestamp token
	ts, err := pkcs9.VerifyOptionalTimestamp(pksig)
	if err != nil {
		return nil, err
	}
	return &VerifiedBlob{
		Blob:      sig,
		Signature: &ts,
		HashFunc:  hashFunc,
	}, nil
}

func hashCheck(h hash.Hash, blob, expected []byte) error {
	h.Reset()
	h.Write(blob)
	actual := h.Sum(nil)
	if hmac.Equal(actual, expected) {
		return nil
	}
	return fmt.Errorf("digest mismatch: expected %x but got %x", expected, actual)
}

func (s *SigBlob) bestDir() *CodeDirectory {
	var dir *CodeDirectory
	for _, dir2 := range s.Directories {
		if dir == nil || dir2.Header.HashType > dir.Header.HashType {
			dir = dir2
		}
	}
	return dir
}

func (s *SigBlob) CodeSize() int64 {
	dir := s.bestDir()
	if dir == nil {
		return 0
	}
	if dir.Header.CodeLimit64 != 0 {
		return dir.Header.CodeLimit64
	}
	return int64(dir.Header.CodeLimit)
}

func (s *SigBlob) VerifyPages(r io.Reader) error {
	dir := s.bestDir()
	if dir == nil {
		return errors.New("no valid code dir found")
	}
	remaining := s.CodeSize()
	if dir.Header.PageSizeLog2 == 0 {
		// single page for DMG bundles
		if len(dir.CodeHashes) != 1 {
			return fmt.Errorf("expected 1 hash slot but found %d", len(dir.CodeHashes))
		}
		h := dir.HashFunc.New()
		n, err := io.Copy(h, r)
		if err != nil {
			return err
		} else if n != remaining {
			return fmt.Errorf("expected code size of %d but got %d", remaining, n)
		}
		computed := h.Sum(nil)
		if !hmac.Equal(computed, dir.CodeHashes[0]) {
			return fmt.Errorf("digest mismatch: expected %x, got %x", dir.CodeHashes[0], computed)
		}
		return nil
	}
	pageSize := int64(1 << dir.Header.PageSizeLog2)
	page := make([]byte, pageSize)
	h := dir.HashFunc.New()
	for i, expected := range dir.CodeHashes {
		if remaining <= 0 {
			return errors.New("not enough hash slots to cover indicated size")
		} else if remaining < pageSize {
			page = page[:remaining]
		}
		if _, err := io.ReadFull(r, page); err != nil {
			return err
		}
		h.Reset()
		h.Write(page)
		computed := h.Sum(nil)
		if !hmac.Equal(computed, expected) {
			return fmt.Errorf("digest mismatch: page %d: expected %x, got %x", i, expected, computed)
		}
		remaining -= int64(len(page))
	}
	return nil
}
