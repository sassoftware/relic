/*
 * Copyright (c) SAS Institute Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package starman

import (
	"archive/tar"
	"errors"
	"io"
	"io/ioutil"
	"strings"

	"github.com/sassoftware/relic/lib/readercounter"
)

const (
	mdPrefix  = ".metadata/"
	sigSuffix = ".sig"
	padSuffix = ".pad"
	blockSize = 512
)

type starmanInfo struct {
	mdblob, sigblob  []byte
	sigStart, sigEnd int64
	mdname           string
	md               TarMD
	hasSig           bool
}

func verifyMeta(r io.Reader) (*starmanInfo, error) {
	info := new(starmanInfo)
	rc := readercounter.New(r)
	tr := tar.NewReader(rc)
	hdr, err := tr.Next()
	if err != nil {
		return nil, err
	} else if !strings.HasPrefix(hdr.Name, mdPrefix) {
		return nil, errors.New("unsupported archive format")
	}
	info.mdname = hdr.Name
	info.mdblob, err = ioutil.ReadAll(tr)
	if err != nil {
		return nil, err
	}
	info.sigStart = (rc.N + blockSize - 1) / blockSize * blockSize

	hdr, err = tr.Next()
	if err != nil && err != io.EOF {
		return nil, err
	} else if hdr.Name == info.mdname+sigSuffix || hdr.Name == info.mdname+padSuffix {
		// read existing signature
		info.sigblob, err = ioutil.ReadAll(tr)
		if err != nil {
			return nil, err
		}
		if hdr.Name == info.mdname+sigSuffix {
			info.hasSig = true
		}
		info.sigEnd = (rc.N + blockSize - 1) / blockSize * blockSize
	} else {
		info.sigEnd = info.sigStart
	}
	if err := info.verifyFiles(tr); err != nil {
		return nil, err
	}
	return info, nil
}
