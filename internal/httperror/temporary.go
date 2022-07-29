package httperror

import (
	"context"
	"errors"
	"io"
	"os"
)

type temporary interface {
	Temporary() bool
}

func Temporary(err error) bool {
	if err == nil {
		return false
	}
	if e, ok := err.(temporary); ok && e.Temporary() {
		return true
	}
	switch {
	case errors.As(err, new(*os.SyscallError)):
		return true
	case errors.Is(err, context.Canceled):
		return true
	case errors.Is(err, context.DeadlineExceeded):
		return true
	case errors.Is(err, io.ErrUnexpectedEOF):
		return true
	}
	return false
}
