# Signing MacOS binaries

relic has preliminary support for signing MacOS and iOS binaries.

For example, to sign a Mac binary for offline distribution,
you will need a Dev ID certificate:

```sh
# Create a signing request:
openssl genrsa -out devid.key 2048
openssl req -new -subj /CN=devid -key devid.key -out devid.csr
# Submit the CSR to https://developer.apple.com/account/resources/certificates/add
# and retrieve the CER, then:
openssl x509 -inform DER -in devid.cer -out devid.crt

# Identify the intermdiate certificate needed:
openssl x509 -in devid.crt -noout -issuer
# e.g. issuer=CN = Developer ID Certification Authority, OU = G2, ...

# Navigate to https://www.apple.com/certificateauthority/
# and find the matching certificate.
# Then fetch and reformat it:
curl -Ls https://www.apple.com/certificateauthority/DeveloperIDG2CA.cer \
  | openssl x509 -inform DER -out intermediate.crt
# Repeat for the root CA:
curl -Ls https://www.apple.com/appleca/AppleIncRootCertificate.cer \
  | openssl x509 -inform DER -out root.crt

# Confirm that the chain is complete:
openssl verify -ignore_critical -CAfile root.crt \
  -untrusted intermediate.crt devid.crt
# devid.crt: OK

# Finally, append the chain to the signing cert:
cat intermediate.crt root.crt >>devid.crt
```

Note that the root CA certificate **must** be included,
otherwise verification errors may occur.

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

Finally, sign a binary or package:

```sh
relic sign -k devid -f foo-darwin-amd64
```

Binaries are signed with the `hardened-runtime` flag by default,
which is required for notarization to succeed.
If this is not desired then it can be disabled
with `--hardened-runtime=false`.

Note also that relic currently does not support signing multi-arch
("fat") binaries, although it can verify them.
Sign each arch separately and then combine them afterwards:

```sh
go install github.com/randall77/makefat@latest
relic sign -f foo-darwin-amd64
relic sign -f foo-darwin-arm64
makefat foo foo-darwin-amd64 foo-darwin-arm64
relic verify foo
```

## Notarization

relic includes a basic tool for submitting bundles to be notarized.
To use it, you first need to generate a team API authentication key
using [App Store Connect](https://appstoreconnect.apple.com/).
Do not use an "individual" key - the notary API only supports team keys.

Then you can bundle your binary or binaries into a ZIP and submit it:

```sh
zip submission.zip binary1 [binary2...]
relic notary submit submission.zip \
  --issuer api-issuer-id \
  --key-id api-key-id \
  --key api-key.p8
```

After completion you can inspect `submission.log` for details about the result.

relic does not currently support ticket stapling,
so consumers of your signed binary must have internet access
to retrieve tickets from the app store directly.

For more information about notarization see
<https://developer.apple.com/documentation/security/notarizing_macos_software_before_distribution/>
and
<https://developer.apple.com/documentation/notaryapi/submitting-software-for-notarization-over-the-web>
