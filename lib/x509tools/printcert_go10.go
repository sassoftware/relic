// +build go1.10
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

package x509tools

import (
	"crypto/x509"
	"fmt"
	"io"
)

func init() {
	extKeyUsageNames[x509.ExtKeyUsageMicrosoftCommercialCodeSigning] = "msCodeCom"
	extKeyUsageNames[x509.ExtKeyUsageMicrosoftKernelCodeSigning] = "msKernCode"
}

func printSAN(w io.Writer, cert *x509.Certificate) {
	if len(cert.DNSNames) != 0 || len(cert.EmailAddresses) != 0 || len(cert.IPAddresses) != 0 || len(cert.URIs) != 0 {
		fmt.Fprintln(w, "  Subject alternate names:")
		for _, s := range cert.DNSNames {
			fmt.Fprintln(w, "    dns:"+s)
		}
		for _, s := range cert.EmailAddresses {
			fmt.Fprintln(w, "    email:"+s)
		}
		for _, s := range cert.IPAddresses {
			fmt.Fprintln(w, "    ip:"+s.String())
		}
		for _, s := range cert.URIs {
			fmt.Fprintln(w, "    uri:"+s.String())
		}
	}
}

func printNameConstraints(w io.Writer, cert *x509.Certificate) {
	if len(cert.PermittedDNSDomains) != 0 || len(cert.ExcludedDNSDomains) != 0 || len(cert.PermittedIPRanges) != 0 || len(cert.ExcludedIPRanges) != 0 || len(cert.PermittedEmailAddresses) != 0 || len(cert.ExcludedEmailAddresses) != 0 || len(cert.PermittedURIDomains) != 0 || len(cert.ExcludedURIDomains) != 0 {
		fmt.Fprintln(w, "  Name constraints:")
		for _, s := range cert.PermittedDNSDomains {
			fmt.Fprintln(w, "     Permitted DNS domain:", s)
		}
		for _, s := range cert.ExcludedDNSDomains {
			fmt.Fprintln(w, "     Excluded DNS domain:", s)
		}
		for _, s := range cert.PermittedIPRanges {
			fmt.Fprintln(w, "     Permitted IP range:", s)
		}
		for _, s := range cert.ExcludedIPRanges {
			fmt.Fprintln(w, "     Excluded IP range:", s)
		}
		for _, s := range cert.PermittedEmailAddresses {
			fmt.Fprintln(w, "     Permitted Email Addresses:", s)
		}
		for _, s := range cert.ExcludedEmailAddresses {
			fmt.Fprintln(w, "     Excluded Email Addresses:", s)
		}
		for _, s := range cert.PermittedURIDomains {
			fmt.Fprintln(w, "     Permitted URI domain:", s)
		}
		for _, s := range cert.ExcludedURIDomains {
			fmt.Fprintln(w, "     Excluded URI domain:", s)
		}
	}
}
