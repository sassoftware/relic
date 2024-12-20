package notary

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/sassoftware/relic/v8/config"
	"github.com/sassoftware/relic/v8/internal/httperror"
	"golang.org/x/oauth2"
)

type Client struct {
	Logger *log.Logger

	cli     *http.Client
	baseURL string
	region  string
}

func NewClient(cfg *config.NotaryConfig) (*Client, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("notary config: %w", err)
	}
	auth, err := newConnectTokenSource(cfg.APIKeyPath, cfg.APIKeyID, cfg.APIIssuerID)
	if err != nil {
		return nil, fmt.Errorf("configuring notary auth: %w", err)
	}
	return &Client{
		Logger:  log.Default(),
		cli:     oauth2.NewClient(context.Background(), auth),
		baseURL: strings.TrimSuffix(cfg.NotaryURL, "/"),
		region:  cfg.SubmissionRegion,
	}, nil
}

func (c *Client) do(req *http.Request, respBody any) error {
	resp, err := c.cli.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// handle HTTP errors
	if resp.StatusCode != http.StatusOK {
		return httperror.FromResponse(resp)
	}
	// read and parse response body
	const maxBody = 100e3
	blob, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return fmt.Errorf("%s %s: reading response: %w", req.Method, req.URL, err)
	}
	if err := json.Unmarshal(blob, respBody); err != nil {
		return fmt.Errorf("%s %s: parsing response: %w", req.Method, req.URL, err)
	}
	return nil
}
