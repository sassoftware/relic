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

package hlkx

const (
	contentTypesPath = "[Content_Types].xml"
	rootRelsPath     = "_rels"
	digSigPath       = "package/services/digital-signature"
	// HLKX uses .psdsor (not .psdor like VSIX)
	originPath  = digSigPath + "/origin.psdsor"
	xmlSigPath  = digSigPath + "/xml-signature"
	xmlCertPath = digSigPath + "/certificate"

	nsDigSig      = "http://schemas.openxmlformats.org/package/2006/digital-signature"
	sigOriginType = "http://schemas.openxmlformats.org/package/2006/relationships/digital-signature/origin"
	sigType       = "http://schemas.openxmlformats.org/package/2006/relationships/digital-signature/signature"
	certType      = "http://schemas.openxmlformats.org/package/2006/relationships/digital-signature/certificate"

	// HLKX uses "application/octet" (not "application/octet-stream" like VSIX)
	defaultContentType = "application/octet"
	tsFormatXML        = "YYYY-MM-DDThh:mm:ss.sTZD"
	tsFormatGo         = "2006-01-02T15:04:05.0-07:00"

	// XML declaration with standalone="yes" as required by HLKX.
	// No trailing newline: PackageDigitalSignatureManager loads the psdsxs with
	// PreserveWhitespace=true, so a newline between the declaration and <Signature>
	// becomes an XmlWhitespace child node, making ChildNodes.Count == 3 and
	// causing an XmlException("Signature structures are corrupted").
	xmlDeclaration = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"

	// OPC/HLKX relationship transform and C14N algorithm URIs
	relTransformAlg = "http://schemas.openxmlformats.org/package/2006/RelationshipTransform"
	c14nAlg         = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
	relsNS          = "http://schemas.openxmlformats.org/package/2006/relationships"
)

var contentTypes = map[string]string{
	"cer":    "application/vnd.openxmlformats-package.digital-signature-certificate",
	"psdsor": "application/vnd.openxmlformats-package.digital-signature-origin",
	"psdsxs": "application/vnd.openxmlformats-package.digital-signature-xmlsignature+xml",
	"rels":   "application/vnd.openxmlformats-package.relationships+xml",
}
