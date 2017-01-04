relic is a multi-tool for package signing and working with hardware security modules (HSMs).

Its features include:

* Generating simple PGP keys in a token
* Signing RPMs using a PGP key in a token
* Generating X509 certificate requests and self-signed certificates in a token
* Supports RSA and ECDSA keys
* Operating as a signing server
* Remotely invoking arbitrary signing tools, like signtool.exe

All features are supported and tested on Linux and Windows, and probably work on other platforms as well.

To install relic:

    go get gerrit-pdt.unx.sas.com/tools/relic.git/relic

To install a version without the PKCS#11 features (more easily cross-compileable):

    go get gerrit-pdt.unx.sas.com/tools/relic.git/relic/relic_notoken

See distro/relic.yml for an example configuration.
