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

package signxap

import "github.com/sassoftware/relic/v7/lib/authenticode"

const (
	trailerMagic = 0x53706158 // XapS
)

var (
	SpcUUIDSipInfoXap = []byte{0x6F, 0xA6, 0x08, 0xBA, 0x3B, 0x11, 0x58, 0x4D, 0x93, 0x29, 0xA1, 0xB3, 0x7A, 0xF3, 0x0F, 0x0E}
	xapSipInfo        = authenticode.SpcSipInfo{A: 1, UUID: SpcUUIDSipInfoXap}
)

type xapTrailer struct {
	Magic       uint32
	Unknown1    uint16
	TrailerSize uint32
}

type xapHeader struct {
	Unknown1, Unknown2 uint16
	SignatureSize      uint32
}
