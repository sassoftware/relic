package csblob

import (
	"crypto/x509"
	"encoding/asn1"
)

// Extensions for specific types of key usage.
// These endorse a leaf certificate to create signatures with the named capability.
// https://images.apple.com/certificateauthority/pdf/Apple_WWDR_CPS_v1.22.pdf
var (
	CodeSign = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 1}

	CodeSignApple                = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 1, 1}
	CodeSignIphoneDev            = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 1, 2}
	CodeSignIphoneApple          = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 1, 3}
	CodeSignIphoneSubmit         = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 1, 4}
	CodeSignSafariExtension      = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 1, 5}
	CodeSignMacAppSubmit         = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 1, 7}
	CodeSignMacInstallerSubmit   = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 1, 8}
	CodeSignMacAppStore          = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 1, 9}
	CodeSignMacAppStoreInstaller = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 1, 10}
	CodeSignMacDev               = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 1, 12}
	CodeSignDevIDExecute         = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 1, 13}
	CodeSignDevIDInstall         = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 1, 14}
	CodeSignDevIDKernel          = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 1, 18}
)

// These endorse an intermediate certificate to sign a certain type of leaf.
var (
	Intermediate = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 2}

	IntermediateWWDR  = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 2, 1}
	IntermediateITMS  = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 2, 2}
	IntermediateAAI   = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 2, 3}
	IntermediateDevID = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 2, 6}
)

// Authenticated attributes found in a signature
var (
	// AttrCodeDirHashPlist holds a plist with (truncated) hashes of each code
	// directory found in the signature
	AttrCodeDirHashPlist = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 9, 1}
	// AttrCodeDirHashes is a set of code directory digests identified by ASN.1
	// algorithm
	AttrCodeDirHashes = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 9, 2}
)

func hasPrefix(id, prefix asn1.ObjectIdentifier) bool {
	if len(id) < len(prefix) {
		return false
	}
	return id[:len(prefix)].Equal(prefix)
}

// MarkHandledExtensions marks proprietary critical extensions as handled so
// that chain verification can proceed
func MarkHandledExtensions(cert *x509.Certificate) {
	var unhandled []asn1.ObjectIdentifier
	for _, ext := range cert.UnhandledCriticalExtensions {
		if !hasPrefix(ext, CodeSign) {
			unhandled = append(unhandled, ext)
		}
	}
	cert.UnhandledCriticalExtensions = unhandled
}

// TeamID returns the team identifier found in an apple-issued leaf certificate,
// or "" if none was found
func TeamID(cert *x509.Certificate) string {
	for _, ext := range cert.Extensions {
		if hasPrefix(ext.Id, CodeSign) {
			// team id should be in the OU field
			if v := cert.Subject.OrganizationalUnit; len(v) == 1 {
				return v[0]
			}
		}
	}
	return ""
}

// RootCA lists known proprietary certificate roots
const RootCA = `-----BEGIN CERTIFICATE-----
MIIEuzCCA6OgAwIBAgIBAjANBgkqhkiG9w0BAQUFADBiMQswCQYDVQQGEwJVUzET
MBEGA1UEChMKQXBwbGUgSW5jLjEmMCQGA1UECxMdQXBwbGUgQ2VydGlmaWNhdGlv
biBBdXRob3JpdHkxFjAUBgNVBAMTDUFwcGxlIFJvb3QgQ0EwHhcNMDYwNDI1MjE0
MDM2WhcNMzUwMjA5MjE0MDM2WjBiMQswCQYDVQQGEwJVUzETMBEGA1UEChMKQXBw
bGUgSW5jLjEmMCQGA1UECxMdQXBwbGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkx
FjAUBgNVBAMTDUFwcGxlIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQDkkakJH5HbHkdQ6wXtXnmELes2oldMVeyLGYne+Uts9QerIjAC6Bg+
+FAJ039BqJj50cpmnCRrEdCju+QbKsMflZ56DKRHi1vUFjczy8QPTc4UadHJGXL1
XQ7Vf1+b8iUDulWPTV0N8WQ1IxVLFVkds5T39pyez1C6wVhQZ48ItCD3y6wsIG9w
tj8BMIy3Q88PnT3zK0koGsj+zrW5DtleHNbLPbU6rfQPDgCSC7EhFi501TwN22IW
q6NxkkdTVcGvL0Gz+PvjcM3mo0xFfh9Ma1CWQYnEdGILEINBhzOKgbEwWOxaBDKM
aLOPHd5lc/9nXmW8Sdh2nzMUZaF3lMktAgMBAAGjggF6MIIBdjAOBgNVHQ8BAf8E
BAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUK9BpR5R2Cf70a40uQKb3
R01/CF4wHwYDVR0jBBgwFoAUK9BpR5R2Cf70a40uQKb3R01/CF4wggERBgNVHSAE
ggEIMIIBBDCCAQAGCSqGSIb3Y2QFATCB8jAqBggrBgEFBQcCARYeaHR0cHM6Ly93
d3cuYXBwbGUuY29tL2FwcGxlY2EvMIHDBggrBgEFBQcCAjCBthqBs1JlbGlhbmNl
IG9uIHRoaXMgY2VydGlmaWNhdGUgYnkgYW55IHBhcnR5IGFzc3VtZXMgYWNjZXB0
YW5jZSBvZiB0aGUgdGhlbiBhcHBsaWNhYmxlIHN0YW5kYXJkIHRlcm1zIGFuZCBj
b25kaXRpb25zIG9mIHVzZSwgY2VydGlmaWNhdGUgcG9saWN5IGFuZCBjZXJ0aWZp
Y2F0aW9uIHByYWN0aWNlIHN0YXRlbWVudHMuMA0GCSqGSIb3DQEBBQUAA4IBAQBc
NplMLXi37Yyb3PN3m/J20ncwT8EfhYOFG5k9RzfyqZtAjizUsZAS2L70c5vu0mQP
y3lPNNiiPvl4/2vIB+x9OYOLUyDTOMSxv5pPCmv/K/xZpwUJfBdAVhEedNO3iyM7
R6PVbyTi69G3cN8PReEnyvFteO3ntRcXqNx+IjXKJdXZD9Zr1KIkIxH3oayPc4Fg
xhtbCS+SsvhESPBgOJ4V9T0mZyCKM2r3DYLP3uujL/lTaltkwGMzd/c6ByxW69oP
IQ7aunMZT7XZNn/Bh1XZp5m5MkL72NVxnn6hUrcbvZNCJBIqxw8dtk2cXmPIS4AX
UKqK1drk/NAJBzewdXUh
-----END CERTIFICATE-----
`
