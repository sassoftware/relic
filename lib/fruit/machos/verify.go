package machos

import (
	"debug/macho"
	"fmt"
	"io"

	"github.com/sassoftware/relic/v7/lib/fruit/csblob"
	"github.com/sassoftware/relic/v7/signers/sigerrors"
)

func Verify(r io.ReaderAt, infoPlist, resources []byte, skipDigests bool) (*csblob.VerifiedBlob, error) {
	hdr, err := macho.NewFile(r)
	if err != nil {
		return nil, err
	}
	buf, err := readSigBlob(r, hdr)
	if err != nil {
		return nil, err
	}
	if infoPlist == nil {
		// check if info.plist is embedded in the image
		infoPlist, err = readPlist(hdr)
		if err != nil {
			return nil, err
		}
	}
	sig, err := csblob.Verify(buf, csblob.VerifyParams{
		InfoPlist: infoPlist,
		Resources: resources,
	})
	if err != nil {
		return nil, fmt.Errorf("verifying mach-O signature: %w", err)
	}
	if !skipDigests {
		r := io.NewSectionReader(r, 0, sig.Blob.CodeSize())
		if err := sig.Blob.VerifyPages(r); err != nil {
			return nil, err
		}
	}
	return sig, nil
}

func readSigBlob(r io.ReaderAt, hdr *macho.File) ([]byte, error) {
	for _, loadCmd := range hdr.Loads {
		raw := loadCmd.Raw()
		cmd := macho.LoadCmd(hdr.ByteOrder.Uint32(raw))
		if cmd != loadCmdCodeSignature {
			continue
		}
		if len(raw) != 16 {
			return nil, fmt.Errorf("expected LC_CODE_SIGNATURE to be 16 bytes not %d bytes", len(raw))
		}
		offset := int64(hdr.ByteOrder.Uint32(raw[8:]))
		length := int64(hdr.ByteOrder.Uint32(raw[12:]))
		if length > 10e6 {
			return nil, fmt.Errorf("unreasonably large LC_CODE_SIGNATURE of %d bytes", length)
		}
		buf := make([]byte, length)
		if _, err := r.ReadAt(buf, offset); err != nil {
			return nil, fmt.Errorf("reading LC_CODE_SIGNATURE: %w", err)
		}
		return buf, nil
	}
	return nil, sigerrors.NotSignedError{Type: "Mach-O"}
}

func readPlist(hdr *macho.File) ([]byte, error) {
	for _, sec := range hdr.Sections {
		if sec.Seg == "__TEXT" && sec.Name == "__info_plist" {
			infoPlist, err := sec.Data()
			if err != nil {
				return nil, fmt.Errorf("reading embedded info_plist: %w", err)
			}
			return infoPlist, nil
		}
	}
	return nil, nil
}
