package notary

import (
	"context"
	"net/http"
	"net/url"
	"time"
)

type StatusCode string

const (
	StatusInProgress StatusCode = "In Progress"
	StatusAccepted   StatusCode = "Accepted"
	StatusRejected   StatusCode = "Rejected"
)

type SubmissionStatus struct {
	Attributes struct {
		CreatedDate time.Time  `json:"createdDate"`
		Name        string     `json:"name"`
		Status      StatusCode `json:"status"`
	} `json:"attributes"`
	ID   string `json:"id"`
	Type string `json:"type"`
}

func (c *Client) GetSubmissionStatus(ctx context.Context, id string) (*SubmissionStatus, error) {
	destURL := c.baseURL + "/submissions/" + url.PathEscape(id)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, destURL, nil)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Data SubmissionStatus `json:"data"`
	}
	if err := c.do(req, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, err
}
