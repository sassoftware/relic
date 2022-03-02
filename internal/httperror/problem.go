package httperror

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// Problem implements a RFC 7087 HTTP "problem" response
type Problem struct {
	Status int    `json:"status"`
	Type   string `json:"type"`

	Title    string `json:"title,omitempty"`
	Detail   string `json:"detail,omitempty"`
	Instance string `json:"instance,omitempty"`
}

func (e Problem) Error() string {
	title := e.Title
	if title == "" {
		title = "[" + e.Type + "]"
	}
	m := fmt.Sprintf("HTTP %d %s", e.Status, title)
	if e.Detail != "" {
		m += ": " + e.Detail
	}
	return m
}

func (e Problem) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	blob, _ := json.Marshal(e)
	rw.Header().Set("Content-Type", "application/problem+json")
	rw.WriteHeader(e.Status)
	_, _ = rw.Write(blob)
}

func (e Problem) Temporary() bool {
	return statusIsTemporary(e.Status)
}

const (
	ProblemKeyUsage = "https://relic.sas.com/key-usage"
)
