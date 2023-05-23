package cosign

import (
	"encoding/json"
	"fmt"

	"github.com/opencontainers/go-digest"
	"github.com/sassoftware/relic/v7/config"
	"github.com/sassoftware/relic/v7/signers"
)

const (
	signatureType          = "cosign container image signature"
	cosignPayloadMediaType = "application/vnd.dev.cosign.simplesigning.v1+json"
	cosignArtifactType     = "application/vnd.dev.cosign.artifact.sig.v1+json"

	// annotations used to encode the signature
	signatureAnnotationKey        = "dev.cosignproject.cosign/signature"
	certificateAnnotationKey      = "dev.sigstore.cosign/certificate"
	chainAnnotationKey            = "dev.sigstore.cosign/chain"
	rfc3161TimestampAnnotationKey = "dev.sigstore.cosign/rfc3161timestamp"
)

func newPayload(manifestDigest digest.Digest, opts signers.SignOpts) ([]byte, error) {
	payload := simpleContainerImage{
		Critical: critical{
			Image: image{DockerManifestDigest: manifestDigest},
			Type:  signatureType,
		},
	}
	// set optionals
	if optional := opts.Flags.GetString("optional"); optional != "" {
		if err := json.Unmarshal([]byte(optional), &payload.Optional); err != nil {
			return nil, fmt.Errorf("invalid annotations: %w", err)
		}
	}
	if payload.Optional == nil {
		payload.Optional = make(map[string]any)
	}
	payload.Optional["creator"] = config.UserAgent
	// record image digest in audit log
	opts.Audit.Attributes["cosign.manifest-digest"] = manifestDigest.String()
	return json.Marshal(payload)
}

// SimpleContainerImage describes the structure of a basic container image signature payload, as defined at:
// https://github.com/containers/image/blob/master/docs/containers-signature.5.md#json-data-format
type simpleContainerImage struct {
	Critical critical       `json:"critical"` // Critical data critical to correctly evaluating the validity of the signature
	Optional map[string]any `json:"optional"` // Optional optional metadata about the image
}

// Critical data critical to correctly evaluating the validity of a signature
type critical struct {
	Image image  `json:"image"` // Image identifies the container that the signature applies to
	Type  string `json:"type"`  // Type must be 'atomic container signature'
}

// Image identifies the container image that the signature applies to
type image struct {
	DockerManifestDigest digest.Digest `json:"docker-manifest-digest"` // DockerManifestDigest the manifest digest of the signed container image
}
