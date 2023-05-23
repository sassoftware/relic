package cosign

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"strings"

	"github.com/opencontainers/image-spec/specs-go"
	oci "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/sassoftware/relic/v7/lib/certloader"
	"github.com/sassoftware/relic/v7/lib/pkcs9"
	"github.com/sassoftware/relic/v7/signers"
)

var signer = &signers.Signer{
	Name:      "cosign",
	CertTypes: signers.CertTypeX509,
	Sign:      sign,
}

func init() {
	signer.Flags().String("optional", "", "extra JSON options to sign")
	signers.Register(signer)
}

func sign(r io.Reader, cert *certloader.Certificate, opts signers.SignOpts) ([]byte, error) {
	// Parse and digest image manifest
	const maxSize = 4 * 1024 * 1024 // spec recommends 4MiB maximum for a manifest
	manifestBlob, err := io.ReadAll(io.LimitReader(r, maxSize+1))
	if err != nil {
		return nil, err
	} else if len(manifestBlob) > maxSize {
		return nil, fmt.Errorf("image manifest exceeds %d bytes", maxSize)
	}
	manifestDigest, manifestType, err := digestManifest(opts.Hash, manifestBlob)
	if err != nil {
		return nil, err
	}
	// Generate the signing payload
	payloadToSign, err := newPayload(manifestDigest, opts)
	if err != nil {
		return nil, err
	}
	// Sign payload
	rawDigest, layerDigest := digestPayload(opts.Hash, payloadToSign)
	rawSignature, err := cert.Signer().Sign(rand.Reader, rawDigest, opts.Hash)
	if err != nil {
		return nil, err
	}
	// Encode payload and signature into an OCI v1.1 manifest
	// https://github.com/opencontainers/image-spec/blob/main/manifest.md#guidelines-for-artifact-usage
	resp := oci.Manifest{
		Versioned:    specs.Versioned{SchemaVersion: 2},
		MediaType:    oci.MediaTypeImageManifest,
		ArtifactType: cosignArtifactType,
		Config:       oci.ScratchDescriptor,
		// Subject is the OCI manifest (image) to which this artifact is attached
		Subject: &oci.Descriptor{
			MediaType: manifestType,
			Digest:    manifestDigest,
			Size:      int64(len(manifestBlob)),
		},
		Layers: []oci.Descriptor{{
			// The signature payload is the contents of the layer
			MediaType: cosignPayloadMediaType,
			Digest:    layerDigest,
			Size:      int64(len(payloadToSign)),
			Data:      payloadToSign,
			// The signature itself is stored in an annotation
			Annotations: map[string]string{
				signatureAnnotationKey: base64.StdEncoding.EncodeToString(rawSignature),
			},
		}},
	}
	if err := attachTimestamp(&resp.Layers[0], cert, opts, rawSignature); err != nil {
		return nil, fmt.Errorf("timestamping failed: %w", err)
	}
	if err := attachCertificates(&resp.Layers[0], cert); err != nil {
		return nil, err
	}
	opts.Audit.SetMimeType(resp.MediaType)
	return json.Marshal(resp)
}

func attachCertificates(layer *oci.Descriptor, cert *certloader.Certificate) error {
	s := new(strings.Builder)
	b := &pem.Block{Type: "CERTIFICATE"}
	for i, certDER := range cert.Chain() {
		b.Bytes = certDER.Raw
		if err := pem.Encode(s, b); err != nil {
			return err
		}
		if i == 0 {
			// leaf
			layer.Annotations[certificateAnnotationKey] = s.String()
			s.Reset()
		} // otherwise keep appending certs to the buffer
	}
	if s.Len() != 0 {
		layer.Annotations[chainAnnotationKey] = s.String()
	}
	return nil
}

func attachTimestamp(layer *oci.Descriptor, cert *certloader.Certificate, opts signers.SignOpts, rawSignature []byte) error {
	if cert.Timestamper == nil {
		return nil
	}
	timestamp, err := cert.Timestamper.Timestamp(opts.Context(), &pkcs9.Request{
		EncryptedDigest: rawSignature,
		Hash:            opts.Hash,
	})
	if err != nil {
		return err
	}
	rawTimestamp, err := timestamp.Marshal()
	if err != nil {
		return err
	}
	counterSig, err := pkcs9.Verify(timestamp, rawSignature, nil)
	if err != nil {
		return fmt.Errorf("timestamp failed signature self-check: %w", err)
	}
	opts.Audit.SetCounterSignature(counterSig)
	layer.Annotations[rfc3161TimestampAnnotationKey] = base64.StdEncoding.EncodeToString(rawTimestamp)
	return nil
}
