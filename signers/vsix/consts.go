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

package vsix

const (
	contentTypesPath = "[Content_Types].xml"
	rootRelsPath     = "_rels"
	digSigPath       = "package/services/digital-signature"
	originPath       = digSigPath + "/origin.psdor"
	xmlSigPath       = digSigPath + "/xml-signature"
	xmlCertPath      = digSigPath + "/certificate"

	nsDigSig      = "http://schemas.openxmlformats.org/package/2006/digital-signature"
	sigOriginType = "http://schemas.openxmlformats.org/package/2006/relationships/digital-signature/origin"
	sigType       = "http://schemas.openxmlformats.org/package/2006/relationships/digital-signature/signature"
	certType      = "http://schemas.openxmlformats.org/package/2006/relationships/digital-signature/certificate"

	defaultContentType = "application/octet-stream"
	tsFormatXML        = "YYYY-MM-DDThh:mm:ss.sTZD"
	tsFormatGo         = "2006-01-02T15:04:05.0-07:00"
)

var contentTypes = map[string]string{
	"cer":    "application/vnd.openxmlformats-package.digital-signature-certificate",
	"psdor":  "application/vnd.openxmlformats-package.digital-signature-origin",
	"psdsxs": "application/vnd.openxmlformats-package.digital-signature-xmlsignature+xml",
	"rels":   "application/vnd.openxmlformats-package.relationships+xml",
}
