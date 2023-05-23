package cosign

import (
	"crypto"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/opencontainers/go-digest"
	oci "github.com/opencontainers/image-spec/specs-go/v1"
)

var algorithms = map[crypto.Hash]digest.Algorithm{
	crypto.SHA256: digest.SHA256,
	crypto.SHA384: digest.SHA384,
	crypto.SHA512: digest.SHA512,
}

// digest a payload and return it both formatted and raw
func digestPayload(hash crypto.Hash, blob []byte) ([]byte, digest.Digest) {
	alg := algorithms[hash]
	if !alg.Available() {
		return nil, ""
	}
	digester := hash.New()
	digester.Write(blob)
	rawDigest := digester.Sum(nil)
	layerDigest := digest.NewDigestFromBytes(alg, rawDigest)
	return rawDigest, layerDigest
}

// legacy container media types
const (
	dockerImageType = "application/vnd.docker.distribution.manifest.v2+json"
	dockerListType  = "application/vnd.docker.distribution.manifest.list.v2+json"
)

var allowedManifestTypes = map[string]bool{
	oci.MediaTypeImageManifest: true,
	oci.MediaTypeImageIndex:    true,
	dockerImageType:            true,
	dockerListType:             true,
}

type objectWithMediaType struct {
	MediaType string `json:"mediaType"`
}

// return the digest and mediaType of a manifest
func digestManifest(hash crypto.Hash, blob []byte) (digest.Digest, string, error) {
	alg := algorithms[hash]
	if !alg.Available() {
		return "", "", fmt.Errorf("unsupported digest %s", hash)
	}
	var mt objectWithMediaType
	if err := json.Unmarshal(blob, &mt); err != nil {
		return "", "", fmt.Errorf("unable to determine mediaType: %w", err)
	}
	if mt.MediaType == "" {
		return "", "", errors.New("unable to determine mediaType")
	}
	if !allowedManifestTypes[mt.MediaType] {
		return "", "", fmt.Errorf("mediaType %q cannot be signed", mt.MediaType)
	}
	return alg.FromBytes(blob), mt.MediaType, nil
}
