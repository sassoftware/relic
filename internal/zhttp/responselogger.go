package zhttp

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"time"
)

// Logger wraps a ResponseWriter and records the resulting status code
// and how many bytes are written
type Logger struct {
	http.ResponseWriter
	length  int64
	status  int
	started time.Time
	Now     func() time.Time
}

// Write implements ResponseWriter
func (l *Logger) Write(d []byte) (size int, err error) {
	if l.status == 0 {
		l.WriteHeader(http.StatusOK)
	}
	size, err = l.ResponseWriter.Write(d)
	l.length += int64(size)
	return
}

// WriteHeader implements ResponseWriter
func (l *Logger) WriteHeader(status int) {
	// suppress duplicate WriteHeader calls, but do save the status code
	if l.status == 0 {
		l.ResponseWriter.WriteHeader(status)
		l.started = l.Now()
	}
	l.status = status
}

// Flush wraps a nested Flusher
func (l *Logger) Flush() {
	if flusher, ok := l.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

// Hijack wraps a nested Hijacker
func (l *Logger) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := l.ResponseWriter.(http.Hijacker); ok {
		conn, rw, err := h.Hijack()
		if err == nil && l.status == 0 {
			l.status = http.StatusSwitchingProtocols
		}
		if hc, ok := conn.(halfCloser); ok {
			// more featureful for tcp.Conn common case
			conn = halfCloseLogger{halfCloser: hc, rl: l}
		} else {
			conn = hijackLogger{Conn: conn, rl: l}
		}
		return conn, rw, err
	}
	return nil, nil, fmt.Errorf("Hijacker interface not supported by type %T", l.ResponseWriter)
}

// CloseNotify wraps a nested CloseNotifier
func (l *Logger) CloseNotify() <-chan bool {
	//nolint // provided for backwards compatibility
	if cn, ok := l.ResponseWriter.(http.CloseNotifier); ok {
		return cn.CloseNotify()
	}
	return make(chan bool)
}

// Push wraps a nested Pusher
func (l *Logger) Push(target string, opts *http.PushOptions) error {
	if p, ok := l.ResponseWriter.(http.Pusher); ok {
		return p.Push(target, opts)
	}
	return fmt.Errorf("Pusher interface not supported by type %T", l.ResponseWriter)
}

// Length returns the number of bytes written
func (l *Logger) Length() int64 {
	return l.length
}

// Status returns the response status
func (l *Logger) Status() int {
	if l.status == 0 {
		return http.StatusOK
	}
	return l.status
}

// Started returns the time at which headers were written
func (l *Logger) Started() time.Time {
	if l.started.IsZero() {
		return l.Now()
	}
	return l.started
}

// hijackLogger wraps a hijacked connection in order to enable WriteErrorReason
// to set the status of the request for logging purposes
type hijackLogger struct {
	net.Conn
	rl *Logger
}

// SetStatus records the final status of a hijacked connection
func (h hijackLogger) SetStatus(status int, length int64) {
	h.rl.status = status
	h.rl.length = length
}

type halfCloser interface {
	net.Conn
	CloseRead() error
	CloseWrite() error
}

// halfCloseLogger wraps a hijacked connection in order to enable
// WriteErrorReason to set the status of the request for logging purposes
type halfCloseLogger struct {
	halfCloser
	rl *Logger
}

// SetStatus records the final status of a hijacked connection
func (h halfCloseLogger) SetStatus(status int, length int64) {
	h.rl.status = status
	h.rl.length = length
}
