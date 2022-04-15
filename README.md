relic is a multi-tool and server for package signing and working with hardware security modules (HSMs).

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
* Mach-O - macOS/iOS signed executables
* DMG, PKG - macOS disk images / installer packages
* APK - Android package
* PGP - inline, detached or cleartext signature of data

# Token types
relic can work with several types of token:

* pkcs11 - Industry standard PKCS#11 HSM interface using shared object files
* Cloud services - AWS, Azure and Google Cloud managed keys
* scdaemon - The GnuPG scdaemon service can enable access to OpenPGP cards (such as Yubikey NEO)
* file - Private keys stored in a password-protected file

# Features
Relic is primarily meant to operate as a signing server, allowing clients to authenticate with a TLS certificate and sign packages remotely. It can also be used as a standalone signing tool.

Other features include:

* Generating and importing keys in the token
* Importing certificate chains from a PKCS#12 file
* Creating X509 certificate signing requests (CSR) and self-signed certificates
* Limited X509 CA support -- signing CSRs and cross-signing certificates
* Creating simple PGP public keys
* RSA and ECDSA supported for all signature types
* Verify signatures, certificate chains and timestamps on all supported package types
* Sending audit logs to an AMQP broker, with an optional sealing signature
* Save token PINs in the system keyring

# Platforms
Linux, Windows and MacOS are supported. Other platforms probably work as well.

relic is tested using libsofthsm2 and Gemalto SafeNet Network HSM (Luna SA). Every vendor PKCS#11 implementation has quirks, so if relic doesn't work with your hardware please submit a pull request.

# Installation
Pre-built client binaries are available from the Github releases page. Alternately, relic can be built from source:

```go install github.com/sassoftware/relic/v7@latest```

The following build tags are also available:

* clientonly - build a lightweight binary without standalone signing features

See [doc/relic.yml](./doc/relic.yml) for an example configuration.

# Additional documentation

* [Signing Android packages](./doc/android.md)
* [Signing MacOS binaries](./doc/macos.md)
* [Using Azure Key Vault](./doc/azure.md)
* [Using a PGP card, YubiKey etc.](./doc/pgpcard.md)

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
