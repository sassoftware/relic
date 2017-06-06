relic is a multi-tool and server for package signing and working with PKCS#11 hardware security modules (HSMs).

# Package types
* RPM - RedHat packages
* DEB - Debian packages
* JAR - Java archives
* EXE (PE/COFF) - Windows executable
* MSI - Windows installer
* appx, appxbundle - Windows universal application
* CAB - Windows cabinet file
* CAT - Windows security catalog
* XAP - Silverlight and legacy Windows Phone applications
* PS1, PS1XML, MOF, etc. - Microsoft Powershell scripts and modules
* manifest, application - Microsoft ClickOnce manifest
* VSIX - Visual Studio extension
* PGP - detached or cleartext signature of data

# Features
Relic is primarily meant to operate as a signing server, allowing clients to authenticate with a TLS certificate and sign packages remotely. It can also be used as a standalone signing tool.

Other features include:

* Generating and importing keys in the token
* Importing certificate chains from a PKCS#12 file
* Creating X509 certificate signing requests (CSR) and self-signed certificates
* Creating simple PGP public keys
* RSA and ECDSA supported for all signature types
* Verify signatures, certificate chains and timestamps on all supported package types
* Sending audit logs to an AMQP broker, with an optional sealing signature
* Save token PINs in the system keyring
* Using file-based private keys instead of a token

# Platforms
Linux and Windows are supported. Other platforms probably work as well.

relic is tested using libsofthsm2 and Gemalto SafeNet "Luna SA" HSMs. Every vendor PKCS#11 implementation has quirks, so if relic doesn't work with your hardware please submit a pull request.

# Installation
1. Install ltdl development headers, i.e.
    a. `dnf install libtool-ltdl-devel` or
    b. `apt-get install libltdl-dev`
2. `go get gerrit-pdt.unx.sas.com/tools/relic.git/relic`

relic can also be built as a client-only tool, removing the dependency on ltdl, by building with `-tags pure` or by disabling cgo.

See distro/linux/relic.yml for an example configuration.

# Related projects
* SoftHSMv2 - file-based PKCS#11 implementation for testing https://github.com/opendnssec/SoftHSMv2
* uts-server - timestamping server for testing https://github.com/kakwa/uts-server
* osslsigncode - Signs EXEs, MSIs, and CABs using openssl https://sourceforge.net/projects/osslsigncode/
* fb-util-for-appx - Builds signed APPX archives https://github.com/facebook/fb-util-for-appx
* OpenVsixSignTool - Sign VSIX extensions using an Azure key vault https://github.com/vcsjones/OpenVsixSignTool

# Reference specifications
* PE/COFF specification - https://www.microsoft.com/en-us/download/details.aspx?id=19509
* Authenticode PE specification - http://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/Authenticode_PE.docx
* Microsoft ClickOnce manifest structure - https://msdn.microsoft.com/en-us/library/dd947276(v=office.12).aspx
* Microsoft Compound File format (for MSI) - https://msdn.microsoft.com/en-us/library/dd942138.aspx
* Alternate reference for compound document format from OpenOffice - https://www.openoffice.org/sc/compdocfileformat.pdf
