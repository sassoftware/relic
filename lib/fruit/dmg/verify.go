package dmg

import (
	"fmt"
	"io"

	"github.com/sassoftware/relic/v7/lib/fruit/csblob"
	"github.com/sassoftware/relic/v7/signers/sigerrors"
)

type Signature struct {
	*csblob.VerifiedBlob
}

func (d *DMG) Verify(skipDigests bool) (*Signature, error) {
	if len(d.sigBlob) == 0 {
		return nil, sigerrors.NotSignedError{Type: "dmg"}
	}
	sig, err := csblob.Verify(d.sigBlob, csblob.VerifyParams{RepSpecific: d.rsf.ForHashing()})
	if err != nil {
		return nil, fmt.Errorf("dmg signature: %w", err)
	}
	if !skipDigests {
		page := io.NewSectionReader(d.r, 0, d.rsf.XMLOffset+d.rsf.XMLLength)
		if err := sig.Blob.VerifyPages(page); err != nil {
			return nil, err
		}
	}
	return &Signature{VerifiedBlob: sig}, nil
}
