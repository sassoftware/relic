package config

import "errors"

const (
	defaultNotaryURL        = "https://appstoreconnect.apple.com/notary/v2"
	defaultSubmissionRegion = "us-west-2"
)

type NotaryConfig struct {
	APIIssuerID string `yaml:",omitempty"`
	APIKeyID    string `yaml:",omitempty"`
	APIKeyPath  string `yaml:",omitempty"`

	NotaryURL        string `yaml:",omitempty"`
	SubmissionRegion string `yaml:",omitempty"`
}

func (n *NotaryConfig) Validate() error {
	var e []error
	if n.APIIssuerID == "" {
		e = append(e, errors.New("API Issuer ID is required"))
	}
	if n.APIKeyID == "" {
		e = append(e, errors.New("API Key ID is required"))
	}
	if n.APIKeyPath == "" {
		e = append(e, errors.New("API Key Path is required"))
	}

	if n.NotaryURL == "" {
		n.NotaryURL = defaultNotaryURL
	}
	if n.SubmissionRegion == "" {
		n.SubmissionRegion = defaultSubmissionRegion
	}
	return errors.Join(e...)
}
