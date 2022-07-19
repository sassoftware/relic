package zhttp

import (
	"context"
	"fmt"
	"net/http"
	"runtime"
	"strings"

	"github.com/rs/zerolog"
)

// RecoveryMiddleware catches panics, logs the error, and writes a generic Internal Server Error response
func RecoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		defer func() {
			if caught := recover(); caught != nil {
				if caught == http.ErrAbortHandler {
					// explicit signal to stop
					panic(caught)
				}
				const size = 64 << 10
				buf := make([]byte, size)
				buf = buf[:runtime.Stack(buf, false)]
				tb := "\n " + strings.Replace(string(buf), "\n", "\n ", -1)
				err, ok := caught.(error)
				if !ok {
					err = fmt.Errorf("%v", caught)
				}
				WriteUnhandledError(rw, req, err, tb)
			}
		}()
		next.ServeHTTP(rw, req)
	})
}

// WriteUnhandledError writes a generic 500 Internal Server Error response while
// logging the actual unhandled error and optional traceback
func WriteUnhandledError(w http.ResponseWriter, req *http.Request, err error, traceback string) {
	status := http.StatusInternalServerError
	field := "error"
	text := "An unhandled exception occurred while processing your request. Please contact your administrator."
	if e := req.Context().Err(); e != nil {
		field = "cancel"
		text = ""
		if e == context.DeadlineExceeded {
			status = http.StatusGatewayTimeout
		} else {
			// borrow nginx's fake 499 status for client closing connection
			status = 499
		}
	}
	AppendAccessLog(req, func(e *zerolog.Event) {
		e.AnErr(field, err)
		if traceback != "" {
			e.Str("stack", traceback)
		}
	})
	http.Error(w, text, status)
}
