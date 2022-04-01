package dmg

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/sassoftware/relic/v7/lib/certloader"
	"github.com/sassoftware/relic/v7/lib/fruit/dmg"
	"github.com/sassoftware/relic/v7/signers"
)

var signer = &signers.Signer{
	Name:      "dmg",
	CertTypes: signers.CertTypeX509,
	TestPath:  testPath,
	Verify:    verify,
	Sign:      sign,
	Transform: transform,
}

func init() {
	signer.Flags().String("bundle-id", "", "(Apple) app bundle ID")
	signer.Flags().String("requirements", "", "(Apple) requirements file to embed (binary only)")
	signers.Register(signer)
}

var fileArgs = []string{"requirements"}

func testPath(s string) bool {
	return strings.HasSuffix(s, ".dmg")
}

func sign(r io.Reader, cert *certloader.Certificate, opts signers.SignOpts) ([]byte, error) {
	args, payload, err := extractFiles(r)
	if err != nil {
		return nil, err
	}
	params := &dmg.SignatureParams{
		HashFunc:        opts.Hash,
		SigningIdentity: opts.Flags.GetString("bundle-id"),
	}
	if v := args["requirements"]; v != nil {
		params.Requirements = v
	}
	udifBytes := args[udifName]
	patch, tsig, err := dmg.Sign(opts.Context(), udifBytes, payload, cert, params)
	if err != nil {
		return nil, err
	}
	opts.Audit.Attributes["mach-o.bundle-id"] = params.SigningIdentity
	opts.Audit.Attributes["mach-o.team-id"] = params.TeamIdentifier
	opts.Audit.SetCounterSignature(tsig.CounterSignature)
	return opts.SetBinPatch(patch)
}

func verify(f *os.File, opts signers.VerifyOpts) ([]*signers.Signature, error) {
	d, err := dmg.Open(f)
	if err != nil {
		return nil, err
	}
	sig, err := d.Verify(opts.NoDigests)
	if err != nil {
		return nil, err
	}
	si := sig.Blob.Directories[0].SigningIdentity
	if t := sig.Blob.Directories[0].TeamIdentifier; t != "" {
		si += fmt.Sprintf("[TeamID:%s]", t)
	}
	if len(sig.Blob.NotaryTicket) > 0 {
		si += "[HasNotaryTicket]"
	}
	for _, unk := range sig.Blob.Unknowns {
		si += fmt.Sprintf("[Unknown:%x.%x]", unk[:4], unk[4:8])
	}
	return []*signers.Signature{{
		Hash:          sig.HashFunc,
		X509Signature: sig.Signature,
		SigInfo:       si,
	}}, nil
}
