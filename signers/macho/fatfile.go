package macho

import (
	"debug/macho"
	"fmt"
	"io"
	"os"

	"github.com/sassoftware/relic/v7/lib/magic"
	"github.com/sassoftware/relic/v7/signers"
)

var fatVerifier = &signers.Signer{
	Name:      "mach-o-fat",
	Magic:     magic.FileTypeMachOFat,
	CertTypes: signers.CertTypeX509,
	Verify:    verifyFatFile,
}

func init() {
	signers.Register(fatVerifier)
}

func verifyFatFile(f *os.File, opts signers.VerifyOpts) ([]*signers.Signature, error) {
	return verifyFat(f, nil, nil, opts)
}

func verifyFat(fr io.ReaderAt, infoPlist, resources []byte, opts signers.VerifyOpts) ([]*signers.Signature, error) {
	fatFile, err := macho.NewFatFile(fr)
	if err == macho.ErrNotFat {
		sig, err := verifyMacho(fr, infoPlist, resources, opts)
		if err != nil {
			return nil, err
		}
		return []*signers.Signature{sig}, nil
	} else if err != nil {
		return nil, err
	}
	var sigs []*signers.Signature
	for _, arch := range fatFile.Arches {
		r := io.NewSectionReader(fr, int64(arch.Offset), int64(arch.Size))
		sig, err := verifyMacho(r, nil, nil, opts)
		if err != nil {
			return nil, fmt.Errorf("%s.%d: %w", arch.Cpu, arch.SubCpu, err)
		}
		sig.Package = fmt.Sprintf("%s.%d", arch.Cpu, arch.SubCpu)
		sigs = append(sigs, sig)
	}
	return sigs, nil
}
