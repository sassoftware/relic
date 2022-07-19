//
// Copyright (c) SAS Institute Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package compresshttp

import (
	"compress/gzip"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"sync/atomic"

	"github.com/golang/snappy"
)

const (
	acceptEncoding   = "Accept-Encoding"
	contentEncoding  = "Content-Encoding"
	contentLength    = "Content-Length"
	EncodingIdentity = "identity"
	EncodingGzip     = "gzip"
	EncodingSnappy   = "x-snappy-framed"

	AcceptedEncodings = EncodingSnappy + ", " + EncodingGzip
)

// higher is better
var prefs = map[string]int{
	EncodingGzip:   1,
	EncodingSnappy: 2,
}

var ErrUnacceptableEncoding = errors.New("unknown Content-Encoding")

func selectEncoding(acceptEncoding string) string {
	var pref int
	var best string
	for _, encoding := range strings.Split(acceptEncoding, ",") {
		encoding = strings.TrimSpace(strings.Split(encoding, ";")[0])
		if p2 := prefs[encoding]; p2 > pref {
			pref = p2
			best = encoding
		}
	}
	return best
}

func setupCompression(encoding string, w io.Writer) (io.WriteCloser, error) {
	switch encoding {
	case EncodingIdentity, "":
		return nopCloseWriter{Writer: w}, nil
	case EncodingGzip:
		return gzip.NewWriterLevel(w, gzip.BestSpeed)
	case EncodingSnappy:
		return snappy.NewBufferedWriter(w), nil
	default:
		return nil, ErrUnacceptableEncoding
	}
}

func compress(encoding string, r io.Reader, w io.Writer) (err error) {
	compr, err := setupCompression(encoding, w)
	if err == nil {
		_, err = io.Copy(compr, r)
	}
	if err == nil {
		err = compr.Close()
	}
	return
}

func decompress(encoding string, r io.Reader) (io.Reader, error) {
	switch encoding {
	case EncodingIdentity, "":
		return ioutil.NopCloser(r), nil
	case EncodingGzip:
		return gzip.NewReader(r)
	case EncodingSnappy:
		return snappy.NewReader(r), nil
	default:
		return nil, ErrUnacceptableEncoding
	}
}

func CompressRequest(request *http.Request, acceptEncoding string) error {
	encoding := selectEncoding(acceptEncoding)
	if encoding == "" {
		return nil
	}
	plain := &readBlocker{Reader: request.Body}
	pr, pw := io.Pipe()
	go func() {
		err := compress(encoding, plain, pw)
		_ = plain.Close()
		_ = pw.CloseWithError(err)
	}()
	// Ensure reads inside the goroutine fail after the request terminates.
	// Otherwise there could be reads happening in parallel from multiple,
	// different requests, if those requests are reading from the same
	// underlying file. That could cause file pointers to move unexpectedly,
	// and it's easier to prevent here than to make sure every use case is
	// thread-safe.
	request.Body = alsoClose{ReadCloser: pr, also: plain}
	request.ContentLength = -1
	request.Header.Set(contentEncoding, encoding)
	return nil
}

// Wrap a reader and block all reads once Close() is called
type readBlocker struct {
	io.Reader
	closed uint32
}

func (r *readBlocker) Read(d []byte) (int, error) {
	if atomic.LoadUint32(&r.closed) != 0 {
		return 0, errors.New("stream is closed")
	}
	return r.Reader.Read(d)
}

func (r *readBlocker) Close() error {
	if c, ok := r.Reader.(io.Closer); ok {
		if err := c.Close(); err != nil {
			return err
		}
	}
	atomic.StoreUint32(&r.closed, 1)
	return nil
}

type alsoClose struct {
	io.ReadCloser
	also io.Closer
}

func (a alsoClose) Close() error {
	a.also.Close()
	return a.ReadCloser.Close()
}

func DecompressRequest(request *http.Request) error {
	r, err := decompress(request.Header.Get(contentEncoding), request.Body)
	if err == nil {
		request.Body = ioutil.NopCloser(r)
		request.ContentLength = -1
	}
	return err
}

func CompressResponse(r io.Reader, acceptEncoding string, writer http.ResponseWriter, status int) error {
	encoding := selectEncoding(acceptEncoding)
	if encoding != "" {
		writer.Header().Set(contentEncoding, encoding)
		writer.Header().Del(contentLength)
	} else {
		writer.Header().Del(contentEncoding)
	}
	writer.WriteHeader(status)
	return compress(encoding, r, writer)
}

func DecompressResponse(response *http.Response) error {
	r, err := decompress(response.Header.Get(contentEncoding), response.Body)
	if err == nil {
		response.Body = readAndClose{r: r, c: response.Body}
		response.ContentLength = -1
	}
	return err
}

type readAndClose struct {
	r io.Reader
	c io.Closer
}

func (rc readAndClose) Read(d []byte) (int, error) {
	return rc.r.Read(d)
}

func (rc readAndClose) Close() error {
	return rc.c.Close()
}

type nopCloseWriter struct {
	io.Writer
}

func (nopCloseWriter) Close() error {
	return nil
}
