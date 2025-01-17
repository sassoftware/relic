package notary

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/sassoftware/relic/v8/internal/httperror"
)

type getLogsResponse struct {
	Data struct {
		Attributes struct {
			DeveloperLogURL string `json:"developerLogUrl"`
		} `json:"attributes"`
		ID   string `json:"id"`
		Type string `json:"type"`
	} `json:"data"`
}

func (c *Client) GetSubmissionLogs(ctx context.Context, id string) (io.ReadCloser, error) {
	// The initial request will return a URL to retrieve the actual log
	destURL := c.baseURL + "/submissions/" + url.PathEscape(id) + "/logs"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, destURL, nil)
	if err != nil {
		return nil, err
	}
	var logsResp getLogsResponse
	if err := c.do(req, &logsResp); err != nil {
		return nil, fmt.Errorf("retrieving log location for %s: %w", id, err)
	}
	logURL := logsResp.Data.Attributes.DeveloperLogURL
	if logURL == "" {
		return nil, fmt.Errorf("missing log URL for submission %s", id)
	}

	// Download the log data
	req, err = http.NewRequestWithContext(ctx, http.MethodGet, logURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching logs: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching logs: %w", httperror.FromResponse(resp))
	}
	return resp.Body, nil
}
