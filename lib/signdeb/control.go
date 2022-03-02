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

package signdeb

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"errors"
	"io"
	"io/ioutil"
	"path"
	"strings"

	"github.com/xi2/xz"
)

type PackageInfo struct {
	Package, Version, Arch string
}

// Parse basic package info from a control.tar.gz stream
func parseControl(r io.Reader, ext string) (*PackageInfo, error) {
	var err error
	switch ext {
	case ".gz":
		r, err = gzip.NewReader(r)
	case ".bz2":
		r = bzip2.NewReader(r)
	case ".xz":
		r, err = xz.NewReader(r, 0)
	case "":
	default:
		err = errors.New("unrecognized compression on control.tar")
	}
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(r)
	found := false
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
		if path.Clean(hdr.Name) == "control" {
			found = true
			break
		}
	}
	if !found {
		return nil, errors.New("control.tar has no control file")
	}
	blob, err := ioutil.ReadAll(tr)
	if err != nil {
		return nil, err
	}
	info := new(PackageInfo)
	scanner := bufio.NewScanner(bytes.NewReader(blob))
	for scanner.Scan() {
		line := scanner.Text()
		i := strings.IndexAny(line, " \t\r\n")
		j := strings.Index(line, ":")
		if j < 0 || i < j {
			continue
		}
		key := line[:j]
		value := strings.Trim(line[j+1:], " \t\r\n")
		switch strings.ToLower(key) {
		case "package":
			info.Package = value
		case "version":
			info.Version = value
		case "architecture":
			info.Arch = value
		}
	}
	if scanner.Err() != nil {
		return nil, scanner.Err()
	}
	if info.Package == "" || info.Version == "" {
		return nil, errors.New("control file is missing package and/or version fields")
	}
	return info, nil
}
