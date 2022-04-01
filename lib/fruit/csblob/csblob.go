package csblob

import (
	"fmt"
	"sort"

	ber "github.com/go-asn1-ber/asn1-ber"

	"github.com/sassoftware/relic/v7/lib/pkcs7"
)

type SigBlob struct {
	// with blob header
	Entitlement     []byte
	EntitlementDER  []byte
	RawRequirements []byte
	NotaryTicket    []byte
	Unknowns        [][]byte

	Directories []*CodeDirectory
	CMS         *pkcs7.ContentInfoSignedData
}

func parseSignature(blob []byte) (*SigBlob, error) {
	magic, items, err := parseSuper(blob)
	if err != nil {
		return nil, err
	}
	if magic != csEmbeddedSignature && magic != csDetachedSignature {
		return nil, fmt.Errorf("expected embedded signature but got %08x", magic)
	}
	sig := new(SigBlob)
	for _, item := range items {
		switch {
		case item.itype == cdRequirementsSlot:
			sig.RawRequirements = item.data
		case item.itype == cdEntitlementSlot:
			sig.Entitlement = item.data
		case item.itype == cdEntitlementDERSlot:
			sig.EntitlementDER = item.data
		case item.itype == cdTicketSlot:
			sig.NotaryTicket = item.data
		case item.itype == cdCodeDirectorySlot || item.itype >= cdAlternateCodeDirectorySlots && item.itype < cdAlternateCodeDirectorySlots+6:
			dir, err := parseCodeDirectory(item.data, item.itype)
			if err != nil {
				return nil, err
			}
			sig.Directories = append(sig.Directories, dir)
		case item.itype == cdSignatureSlot:
			if len(item.data) <= 8 {
				sig.CMS = nil
				continue
			}
			// For some inane reason signatures are encoded with an indefinite
			// length content, which go's asn1 lib chokes on because it's not
			// DER. Use BER library to reencode.
			pkt, err := ber.DecodePacketErr(item.data[8:])
			if err != nil {
				return nil, err
			}
			der := pkt.Bytes()
			psd, err := pkcs7.Unmarshal(der)
			if err != nil {
				return nil, err
			}
			sig.CMS = psd
		default:
			sig.Unknowns = append(sig.Unknowns, item.data)
		}
	}
	sort.Slice(sig.Directories, func(i, j int) bool {
		return sig.Directories[i].IType < sig.Directories[j].IType
	})
	return sig, nil
}
