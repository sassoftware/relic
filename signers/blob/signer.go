package blob

import (

	"io"
	"os"
	"fmt"
	"errors"
	"crypto"
	"crypto/rand"

	"github.com/rs/zerolog"
	"github.com/sassoftware/relic/v8/lib/audit"
	"github.com/sassoftware/relic/v8/lib/certloader"
	"github.com/sassoftware/relic/v8/signers"
	"github.com/sassoftware/relic/v8/lib/atomicfile"
	"github.com/sassoftware/relic/v8/lib/binpatch"

)


var BlobSigner = &signers.Signer{
	Name:	    "blob",
	CertTypes:  signers.CertTypePgp,
	AllowStdin: true,
	Transform:  transform,
	Sign:	    sign,
	Verify:	    verify,
}

func init() {
	signers.Register(BlobSigner)
}

func formatLog(attrs *audit.Info) *zerolog.Event {
	return attrs.AttrsForLog("blob.")
}

func sign(r io.Reader, cert *certloader.Certificate, opts signers.SignOpts) ([]byte, error) {
	privKey := cert.PrivateKey.(crypto.Signer)
	hash := opts.Hash.New()
	if _, err := io.Copy(hash, r); err != nil {
		return nil, err
	}
	digest := hash.Sum(nil)
	return privKey.Sign(rand.Reader, digest, opts.Hash)
}

func verify(f *os.File, opts signers.VerifyOpts) ([]*signers.Signature, error) {
	return nil, errors.New("Not implemented")
}

type blobTransformer struct {
	input *os.File
}

func transform(f *os.File, opts signers.SignOpts) (signers.Transformer, error) {
	//save input filename for later use
	return &blobTransformer{f}, nil
}

func (t blobTransformer) GetReader() (io.Reader, error) {
	if _, err := t.input.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("seeking input file: %w", err)
	}
	return t.input, nil
}

func (t *blobTransformer) Apply(dest, mimeType string, result io.Reader) error {
	var output string
	// avoid mangling input file
	if t.input.Name() == dest {
		output = "-"
	} else {
		output = dest
	}

	// copy from default implementation in signers/transform
	if mimeType == binpatch.MimeType {
		return signers.ApplyBinPatch(t.input, dest, result)
	}
	f, err := atomicfile.WriteAny(output)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, result); err != nil {
		return err
	}
	t.input.Close()
	return f.Commit()
}

