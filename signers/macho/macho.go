package macho

import (
	"fmt"
	"io"
	"os"

	"github.com/sassoftware/relic/v7/lib/certloader"
	"github.com/sassoftware/relic/v7/lib/fruit/csblob"
	"github.com/sassoftware/relic/v7/lib/fruit/machos"
	"github.com/sassoftware/relic/v7/lib/magic"
	"github.com/sassoftware/relic/v7/signers"
)

var signer = &signers.Signer{
	Name:      "mach-o",
	Magic:     magic.FileTypeMachO,
	CertTypes: signers.CertTypeX509,
	Transform: transform,
	Sign:      sign,
	Verify:    verifyMachoFile,
}

func init() {
	signer.Flags().String("bundle-id", "", "(Apple) app bundle ID")
	signer.Flags().String("info-plist", "", "(Apple) Info.plist file to bind to the signature")
	signer.Flags().String("entitlements", "", "(Apple) entitlements file to embed")
	signer.Flags().Bool("hardened-runtime", false, "(Apple) enable hardened runtime")
	signer.Flags().String("requirements", "", "(Apple) requirements file to embed (binary only)")
	signer.Flags().String("resources", "", "(Apple) CodeResources file to bind to the signature")
	signers.Register(signer)
}

var fileArgs = []string{"info-plist", "entitlements", "requirements", "resources"}

func sign(r io.Reader, cert *certloader.Certificate, opts signers.SignOpts) ([]byte, error) {
	args, exec, err := extractFiles(r)
	if err != nil {
		return nil, err
	}
	params := &csblob.SignatureParams{
		HashFunc:        opts.Hash,
		SigningIdentity: opts.Flags.GetString("bundle-id"),
	}
	if v := args["info-plist"]; v != nil {
		params.InfoPlist = v
	}
	if v := args["entitlements"]; v != nil {
		params.Entitlement = v
	}
	if v := args["requirements"]; v != nil {
		params.Requirements = v
	}
	if v := args["resources"]; v != nil {
		params.Resources = v
	}
	if opts.Flags.GetBool("hardened-runtime") {
		params.Flags |= csblob.FlagRuntime
	}
	patch, tsig, err := machos.Sign(opts.Context(), exec, cert, params)
	if err != nil {
		return nil, err
	}
	opts.Audit.Attributes["mach-o.bundle-id"] = params.SigningIdentity
	opts.Audit.Attributes["mach-o.team-id"] = params.TeamIdentifier
	opts.Audit.SetCounterSignature(tsig.CounterSignature)
	return opts.SetBinPatch(patch)
}

func verifyMachoFile(f *os.File, opts signers.VerifyOpts) ([]*signers.Signature, error) {
	sig, err := verifyMacho(f, nil, nil, opts)
	if err != nil {
		return nil, err
	}
	return []*signers.Signature{sig}, nil
}

func verifyMacho(r io.ReaderAt, infoPlist, resources []byte, opts signers.VerifyOpts) (*signers.Signature, error) {
	sig, err := machos.Verify(r, infoPlist, resources, opts.NoDigests)
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
	if sig.Blob.Directories[0].Header.Flags&csblob.FlagRuntime != 0 {
		si += "[HardenedRuntime]"
	}
	for _, unk := range sig.Blob.Unknowns {
		si += fmt.Sprintf("[Unknown:%x.%x]", unk[:4], unk[4:8])
	}
	return &signers.Signature{
		Hash:          sig.HashFunc,
		X509Signature: sig.Signature,
		SigInfo:       si,
	}, nil
}
