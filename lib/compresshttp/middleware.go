package compresshttp

import (
	"io"
	"log"
	"net/http"
)

func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(acceptEncoding, AcceptedEncodings)
		// decompress request
		if err := DecompressRequest(r); err == ErrUnacceptableEncoding {
			http.Error(w, "invalid content-encoding", http.StatusUnsupportedMediaType)
			return
		} else if err != nil {
			log.Printf("error: decoding request from %s: %+v", r.RemoteAddr, err)
			http.Error(w, "failed to decompress request", http.StatusBadRequest)
			return
		}
		// choose response encoding
		encoding := selectEncoding(r.Header.Get(acceptEncoding))
		if encoding == "" || encoding == EncodingIdentity {
			// shortcut if no encoding is possible
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Del("Content-Length")
		// wrap writer in compression and call handler
		wrapped := &responseCompressor{
			rw:       w,
			encoding: encoding,
		}
		next.ServeHTTP(wrapped, r)
		// flush
		if err := wrapped.Close(); err != nil {
			log.Printf("error: flushing response to %s: %+v", r.RemoteAddr, err)
		}
	})
}

type responseCompressor struct {
	rw http.ResponseWriter
	wc io.WriteCloser

	encoding    string
	wroteHeader bool
}

func (w *responseCompressor) WriteHeader(status int) {
	if !w.wroteHeader {
		if status >= 300 {
			// don't compress errors
			w.encoding = ""
		} else if w.encoding != "" && w.encoding != EncodingIdentity {
			w.Header().Set(contentEncoding, w.encoding)
		}
		w.wroteHeader = true
	}
	w.rw.WriteHeader(status)
}

func (w *responseCompressor) Write(d []byte) (int, error) {
	// wait until the first byte to start compressing so that it can be
	// selectively disabled in the case of errors
	if w.wc == nil {
		if !w.wroteHeader {
			w.Header().Set(contentEncoding, w.encoding)
			w.rw.WriteHeader(http.StatusOK)
			w.wroteHeader = true
		}
		var err error
		w.wc, err = setupCompression(w.encoding, w.rw)
		if err != nil {
			return 0, err
		}
	}
	return w.wc.Write(d)
}

func (w *responseCompressor) Header() http.Header {
	return w.rw.Header()
}

func (w *responseCompressor) Flush() {
	// flush compressor
	if flusher, ok := w.wc.(flusher); ok {
		if err := flusher.Flush(); err != nil {
			log.Println("warning: flushing compressor:", err)
		}
	}
	// flush response
	if flusher, ok := w.rw.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *responseCompressor) Close() error {
	if w.wc == nil {
		return nil
	}
	return w.wc.Close()
}

type flusher interface {
	Flush() error
}
