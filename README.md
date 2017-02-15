relic is a multi-tool and server for package signing and working with PKCS#11 hardware security modules (HSMs).

It can sign these package types:

* RPM
* DEB
* JAR
* PE/COFF (Windows executable)
* PGP (detached or cleartext signature of data)

Relic can also operate as a signing server, allowing clients to authenticate
with a TLS certificate and sign packages remotely. Preconfigured tools can also
be invoked by the server, e.g. signtool.exe, to perform operations not directly
supported by relic.

Other features include:

* Generating and importing keys in the token
* Creating X509 certificate signing requests (CSR) and self-signed certificates
* Creating simple PGP public keys
* RSA and ECDSA supported for all signature types
* Verify signatures on all supported package types

Linux and Windows are supported. Other platforms probably work as well.

To install relic:

    go get gerrit-pdt.unx.sas.com/tools/relic.git/relic

To install a version without the PKCS#11 features (more easily cross-compileable):

    go get gerrit-pdt.unx.sas.com/tools/relic.git/relic/relic_notoken

See distro/linux/relic.yml for an example configuration.
