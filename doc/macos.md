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
    timestamper: apple

tokens:
  file:
    type: file
timestamp:
  namedurls:
    apple:
      - http://timestamp.apple.com/ts01
```

    relic sign -k devid -f foo-darwin-amd64

Binaries are signed with the `hardened-runtime` flag by default, which is required for notarization to succeed.
If this is not desired then it can be disabled with `--hardened-runtime=false`.

Note also that relic currently does not support signing multi-arch ("fat") binaries, although it can verify them.
Sign each arch separately and then combine them afterwards:

    go install github.com/randall77/makefat@latest
    relic sign -f foo-darwin-amd64
    relic sign -f foo-darwin-arm64
    makefat foo foo-darwin-amd64 foo-darwin-arm64
    relic verify foo

The signed binary can then be placed into a regular zip file and uploaded for notarization.
