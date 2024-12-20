package notary

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

type NewSubmissionResponse struct {
	Attributes UploadAttributes `json:"attributes"`
	ID         string           `json:"id"`
	Type       string           `json:"type"`
}

type UploadAttributes struct {
	AWSAccessKeyID     string `json:"awsAccessKeyId"`
	AWSSecretAccessKey string `json:"awsSecretAccessKey"`
	AWSSessionToken    string `json:"awsSessionToken"`
	Bucket             string `json:"bucket"`
	Object             string `json:"object"`
}

func (a *UploadAttributes) Validate() error {
	var e []error
	if a.AWSAccessKeyID == "" {
		e = append(e, errors.New("missing awsAccessKeyId"))
	}
	if a.AWSSecretAccessKey == "" {
		e = append(e, errors.New("missing awsSecretAccessKey"))
	}
	if a.AWSSessionToken == "" {
		e = append(e, errors.New("missing awsSessionToken"))
	}
	if a.Bucket == "" {
		e = append(e, errors.New("missing bucket"))
	}
	if a.Object == "" {
		e = append(e, errors.New("missing object"))
	}
	return errors.Join(e...)
}

type newSubmissionRequest struct {
	SHA256         string `json:"sha256"`
	SubmissionName string `json:"submissionName"`
}

// NewSubmission initiates a submission for the given file and returns
// attributes used to upload it for evaluation.
func (c *Client) NewSubmission(ctx context.Context, name, sha256sum string) (*NewSubmissionResponse, error) {
	reqBody := newSubmissionRequest{
		SHA256:         sha256sum,
		SubmissionName: name,
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("building submission request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/submissions", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("building submission request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	var resp struct {
		Data NewSubmissionResponse `json:"data"`
	}
	if err := c.do(req, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, err
}

// SubmitFile initiates a submission and uploads its contents without waiting
// for it to finish. Returns the ID of the submission.
func (c *Client) SubmitFile(ctx context.Context, name string, f io.ReadSeeker) (string, error) {
	digest := sha256.New()
	if _, err := io.Copy(digest, f); err != nil {
		return "", fmt.Errorf("digesting %s: %w", name, err)
	}
	sha256sum := hex.EncodeToString(digest.Sum(nil))
	// Rewind for the upload
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	// Initiate submission
	submission, err := c.NewSubmission(ctx, name, sha256sum)
	if err != nil {
		return "", fmt.Errorf("submitting %q: %w", name, err)
	}
	// Upload contents
	if err := c.Upload(ctx, &submission.Attributes, f); err != nil {
		return "", fmt.Errorf("uploading %q: %w", name, err)
	}
	return submission.ID, nil
}
