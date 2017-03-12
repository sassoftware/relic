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

package signappx

import (
	"encoding/xml"
	"fmt"

	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/x509tools"
)

type appxPackage struct {
	XmlName xml.Name

	Identity appxIdentity

	DisplayName          string `xml:"Properties>DisplayName"`
	PublisherDisplayName string `xml:"Properties>PublisherDisplayName"`
	Logo                 string `xml:"Properties>Logo"`
}

type appxIdentity struct {
	Name                  string `xml:",attr"`
	Publisher             string `xml:",attr"`
	Version               string `xml:",attr"`
	ProcessorArchitecture string `xml:",attr"`
}

func parseManifest(files zipFiles, sig *AppxSignature) error {
	blob, err := readZipFile(files[appxManifest])
	if err != nil {
		return fmt.Errorf("appx manifest: %s", err)
	}
	var manifest appxPackage
	if err := xml.Unmarshal(blob, &manifest); err != nil {
		return fmt.Errorf("appx manifest: %s", err)
	}
	sig.Name = manifest.Identity.Name
	sig.DisplayName = manifest.DisplayName
	sig.Version = manifest.Identity.Version
	publisher := x509tools.FormatPkixName(sig.Signature.Certificate.RawSubject, x509tools.NameStyleMsOsco)
	if manifest.Identity.Publisher != publisher {
		return fmt.Errorf("appx manifest: publisher identity mismatch:\nexpected: %s\nactual: %s", publisher, manifest.Identity.Publisher)
	}
	return nil
}
