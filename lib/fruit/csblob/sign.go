package csblob

import (
	"context"
	"crypto"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"time"

	"howett.net/plist"

	"github.com/sassoftware/relic/v7/lib/certloader"
	"github.com/sassoftware/relic/v7/lib/pkcs7"
	"github.com/sassoftware/relic/v7/lib/pkcs9"
	"github.com/sassoftware/relic/v7/lib/x509tools"
)

type SignatureParams struct {
	Pages        io.Reader // read page contents
	OldSignature io.Reader // read the existing signature, if any, after the pages
	HashFunc     crypto.Hash
	InfoPlist    []byte // manifest to bind to signature
	Resources    []byte // CodeResources to bind to signature

	// the following are copied from the old signature if empty
	Flags            SignatureFlags
	Requirements     []byte // requirements to embed in signature
	Entitlement      []byte // entitlement to embed in signature
	EntitlementDER   []byte // entitlement in DER format
	RepSpecific      []byte // DMG header
	SigningIdentity  string // bundle ID
	TeamIdentifier   string // team ID from signing cert (set automatically if empty)
	ExecSegmentBase  int64
	ExecSegmentLimit int64
	ExecSegmentFlags int64
}

func (p *SignatureParams) hashFuncs() []crypto.Hash {
	return []crypto.Hash{p.HashFunc}
}

func (p *SignatureParams) DefaultsFromSignature() error {
	// parse old signature
	if p.OldSignature == nil {
		return nil
	}
	blob, err := ioutil.ReadAll(p.OldSignature)
	if err != nil {
		return err
	}
	oldSig, err := parseSignature(blob)
	if err != nil {
		return err
	}
	// copy embedded items
	if p.Entitlement == nil && oldSig.Entitlement != nil {
		p.Entitlement = oldSig.Entitlement[8:]
		if p.EntitlementDER == nil && oldSig.EntitlementDER != nil {
			// copy DER only if xml entitlements were also not set
			p.EntitlementDER = oldSig.EntitlementDER[8:]
		}
	}
	// copy code dir fields
	oldDir := oldSig.bestDir()
	if oldDir == nil {
		return nil
	}
	if p.Flags == 0 {
		p.Flags = oldDir.Header.Flags &^ clearFlags
	}
	if p.ExecSegmentBase == 0 && p.ExecSegmentLimit == 0 && p.ExecSegmentFlags == 0 {
		p.ExecSegmentBase = oldDir.Header.ExecSegmentBase
		p.ExecSegmentLimit = oldDir.Header.ExecSegmentLimit
		p.ExecSegmentFlags = oldDir.Header.ExecSegmentFlags
	}
	return nil
}

func (p *SignatureParams) DefaultsFromBundle(cert *certloader.Certificate) error {
	if p.SigningIdentity == "" && len(p.InfoPlist) != 0 {
		var bundle bundlePlist
		if _, err := plist.Unmarshal(p.InfoPlist, &bundle); err != nil {
			return fmt.Errorf("info.plist: %w", err)
		}
		p.SigningIdentity = bundle.BundleID
	}
	if p.TeamIdentifier == "" {
		p.TeamIdentifier = TeamID(cert.Leaf)
	}
	if p.Requirements == nil {
		req, err := DefaultRequirement(p.SigningIdentity, cert.Chain())
		if err != nil {
			return fmt.Errorf("computing default designated requirement: %w", err)
		}
		p.Requirements = req
	}
	return nil
}

const defaultPageSizeLog2 = 12

func Sign(ctx context.Context, cert *certloader.Certificate, params *SignatureParams) ([]byte, *pkcs9.TimestampedSignature, error) {
	// hash code pages
	hashFuncs := params.hashFuncs()
	singlePage := params.RepSpecific != nil // DMG
	codeSlots, slotCount, codeLimit, err := hashPages(hashFuncs, params.Pages, singlePage)
	if err != nil {
		return nil, nil, fmt.Errorf("hashing code pages: %w", err)
	}
	// read the old signature to extract entitlements etc.
	if err := params.DefaultsFromSignature(); err != nil {
		return nil, nil, fmt.Errorf("parsing old signature: %w", err)
	}
	if err := params.DefaultsFromBundle(cert); err != nil {
		return nil, nil, fmt.Errorf("setting signature params: %w", err)
	}
	// build list of special slots to hash. for these the hash covers the blob
	// header as well so they have to be marshalled here
	var entBlob, entDERBlob, reqBlob []byte
	var hashedItems []superItem
	if params.Requirements != nil {
		v := params.Requirements
		if len(v) < 8 {
			return nil, nil, errors.New("requirements blob must be a binary requirement or requirement set")
		}
		switch csMagic(binary.BigEndian.Uint32(v)) {
		case csRequirements:
			// already a set of requirements
		case csRequirement:
			// assume single requirement is the DR
			j := newSuperItem(csRequirement, v[8:])
			j.itype = uint32(DesignatedRequirement)
			v = marshalSuperBlob(csRequirements, []superItem{j})
		default:
			return nil, nil, errors.New("requirements blob must be a binary requirement or requirement set")
		}
		// strip off the superblob header and let marshalSuperBlob put it back on
		i := newSuperItem(csRequirements, v[8:])
		reqBlob = i.data
		hashedItems = append(hashedItems, i)
	}
	if params.Entitlement != nil {
		i := newSuperItem(csEntitlement, params.Entitlement)
		entBlob = i.data
		hashedItems = append(hashedItems, i)
	}
	if params.EntitlementDER != nil {
		i := newSuperItem(csEntitlementDER, params.EntitlementDER)
		entDERBlob = i.data
		hashedItems = append(hashedItems, i)
	}
	specials := [][]byte{
		entDERBlob,         // -7 entitlements DER
		params.RepSpecific, // -6 DMG
		entBlob,            // -5 entitlements
		nil,                // -4 app-specific
		params.Resources,   // -3 resource manifest
		reqBlob,            // -2 requirements
		params.InfoPlist,   // -1 info manifest
	}
	for specials[0] == nil && len(specials) > 5 {
		specials = specials[1:]
	}
	var plistHashes cdHashPlist
	var attrHashes []cdHashAttrib
	var firstCD []byte
	var items []superItem
	for i, hashFunc := range hashFuncs {
		cdParams := codeDirParams{
			SignatureParams: params,
			Specials:        specials,
			CodeSlots:       codeSlots[i],
			CodeSlotCount:   slotCount,
			CodeLimit:       codeLimit,
			HashFunc:        hashFunc,
			SinglePage:      singlePage,
		}
		result, err := newCodeDirectory(cdParams)
		if err != nil {
			return nil, nil, fmt.Errorf("populating code directory: %w", err)
		}
		alg, ok := x509tools.PkixDigestAlgorithm(hashFunc)
		if !ok {
			return nil, nil, fmt.Errorf("unsupported algorithm %s", hashFunc)
		}
		attrHashes = append(attrHashes, cdHashAttrib{
			Algorithm: alg.Algorithm,
			Digest:    result.Digest,
		})
		plistHashes.CDHashes = append(plistHashes.CDHashes, result.Digest[:20])
		item := superItem{magic: csCodeDirectory, data: result.Raw}
		if i == 0 {
			firstCD = item.data
			item.itype = cdCodeDirectorySlot
		} else {
			item.itype = uint32(cdAlternateCodeDirectorySlots + i - 1)
		}
		items = append(items, item)
	}
	items = append(items, hashedItems...)
	// sign
	builder := pkcs7.NewBuilder(cert.Signer(), cert.Chain(), params.HashFunc)
	if err := builder.SetContentData(firstCD); err != nil {
		return nil, nil, err
	}
	if err := addCSHashes(builder, attrHashes); err != nil {
		return nil, nil, fmt.Errorf("adding cdhashes: %w", err)
	}
	if err := addPlistHashes(builder, plistHashes); err != nil {
		return nil, nil, fmt.Errorf("adding cdhash plist: %w", err)
	}
	if err := builder.AddAuthenticatedAttribute(pkcs7.OidAttributeSigningTime, time.Now().UTC()); err != nil {
		return nil, nil, err
	}
	psd, err := builder.Sign()
	if err != nil {
		return nil, nil, err
	}
	tssig, err := pkcs9.TimestampAndMarshal(ctx, psd, cert.Timestamper, false)
	if err != nil {
		return nil, nil, err
	}
	// marshal
	if _, err := psd.Detach(); err != nil {
		return nil, nil, err
	}
	tssig.Raw, err = psd.Marshal()
	if err != nil {
		return nil, nil, err
	}
	items = append(items, newSuperItem(csBlobWrapper, tssig.Raw))
	blob := marshalSuperBlob(csEmbeddedSignature, items)
	return blob, tssig, err
}

type bundlePlist struct {
	Executable string `plist:"CFBundleExecutable"`
	BundleID   string `plist:"CFBundleIdentifier"`
}
