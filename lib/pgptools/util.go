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

package pgptools

import "golang.org/x/crypto/openpgp"

// Return the primary identity name of a PGP entity
func EntityName(entity *openpgp.Entity) string {
	if entity == nil {
		return ""
	}
	var name string
	for _, ident := range entity.Identities {
		if name == "" {
			name = ident.Name
		}
		if ident.SelfSignature.IsPrimaryId != nil && *ident.SelfSignature.IsPrimaryId {
			return ident.Name
		}
	}
	return name
}
