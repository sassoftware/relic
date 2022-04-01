package xar

import (
	"io"
	"os"

	"github.com/sassoftware/relic/v7/lib/certloader"
	"github.com/sassoftware/relic/v7/lib/fruit/csblob"
	"github.com/sassoftware/relic/v7/lib/fruit/xar"
	"github.com/sassoftware/relic/v7/lib/magic"
	"github.com/sassoftware/relic/v7/signers"
)

var signer = &signers.Signer{
	Name:      "xar",
	Magic:     magic.FileTypeXAR,
	CertTypes: signers.CertTypeX509,
	Sign:      sign,
	Verify:    verify,
}

func init() {
	signers.Register(signer)
}

func sign(r io.Reader, cert *certloader.Certificate, opts signers.SignOpts) ([]byte, error) {
	patch, tsig, err := xar.Sign(opts.Context(), r, cert, opts.Hash)
	if err != nil {
		return nil, err
	}
	if teamID := csblob.TeamID(cert.Leaf); teamID != "" {
		opts.Audit.Attributes["mach-o.team-id"] = teamID
	}
	opts.Audit.SetCounterSignature(tsig.CounterSignature)
	return opts.SetBinPatch(patch)
}

func verify(f *os.File, opts signers.VerifyOpts) ([]*signers.Signature, error) {
	size, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		return nil, err
	}
	x, err := xar.Open(f, size)
	if err != nil {
		return nil, err
	}
	sig, err := x.Verify(opts.NoDigests)
	if err != nil {
		return nil, err
	}
	var si string
	if len(sig.NotaryTicket) > 0 {
		si += "[HasNotaryTicket]"
	}
	return []*signers.Signature{{
		Hash:          sig.HashFunc,
		X509Signature: sig.Signature,
		SigInfo:       si,
	}}, nil
}
