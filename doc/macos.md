# Signing MacOS binaries
relic has preliminary support for signing MacOS and iOS binaries.

For example, to sign a Mac binary for offline distribution, you will need a DevID certificate.
Configure relic to use the cert with Apple's timestamp servers:

```yaml
keys:
  devid:
    token: file
    x509certificate: ./devid.crt
    keyfile: ./devid.key
    timestamp: true

tokens:
  file:
    type: file
timestamp:
  urls:
    - http://timestamp.apple.com/ts01
```

Binaries should be signed with the `hardened-runtime` flag is set or notarization will fail:

    relic sign -k devid -f foo-darwin-amd64 --hardened-runtime

Note also that relic currently does not support signing multi-arch ("fat") binaries, although it can verify them.
Sign each arch separately and then combine them afterwards:

    go install github.com/randall77/makefat@latest
    makefat foo foo-darwin-amd64 foo-darwin-arm64
    relic verify foo

The signed binary can then be placed into a regular zip file and uploaded for notarization.