package httperror

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type ResponseError struct {
	Method     string
	URL        string
	Status     string
	StatusCode int
	BodyText   string
}

func (e ResponseError) Error() string {
	return fmt.Sprintf("HTTP error:\n%s %s\n%s\n%s", e.Method, e.URL, e.Status, e.BodyText)
}

func (e ResponseError) Temporary() bool {
	return statusIsTemporary(e.StatusCode)
}

func FromResponse(resp *http.Response) error {
	defer resp.Body.Close()
	blob, err := io.ReadAll(io.LimitReader(resp.Body, 100000))
	if err != nil {
		return err
	}
	if strings.Contains(resp.Header.Get("Content-Type"), "problem+json") {
		var p Problem
		if err := json.Unmarshal(blob, &p); err == nil {
			if p.Status == 0 {
				p.Status = resp.StatusCode
			}
			return p
		}
	}
	return ResponseError{
		Method:     resp.Request.Method,
		URL:        resp.Request.URL.String(),
		Status:     resp.Status,
		StatusCode: resp.StatusCode,
		BodyText:   string(blob),
	}
}

func statusIsTemporary(code int) bool {
	switch code {
	case http.StatusGatewayTimeout,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusInsufficientStorage,
		http.StatusInternalServerError:
		return true
	default:
		return false
	}
}
