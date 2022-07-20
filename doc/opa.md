# Open Policy Agent

relic can optionally replace its builtin certificate-based authentication with [Open Policy Agent](https://www.openpolicyagent.org/docs/latest/).

OPA is a flexible policy engine that evaluates centrally-distributed, user-defined rules
from a sidecar daemon. relic can use this to make certificate-based auth more dynamic
and CI/CD-friendly, to add support for Azure AD and other token-based authentication, or both.

To enable OPA in relic, set a URL to the policy to evaluate in the server configuration:

```yaml
server:
  policyurl: http://127.0.0.1/v1/data/relic
```

policyurl can point either at a specific package,
or at the root of the server to use the default decision.

relic will provide the following inputs to the policy:

- token - The Bearer token provided in the `Authorization` header, if provided
- fingerprint - Digest of the client's leaf certificate, if provided
- path - Path from the URL being accessed
- query - Query parameters from the URL being accessed

The policy may provide the following fields in return:

- allow - true if the request should proceed
- sub - a string describing the subject or user that authenticated
- claims - a map of further key-value pairs describing the authenticated user
- errors - an array of strings indicating any errors explaining why the request was denied
- roles - an array of strings specifying which key roles the user may access
- allowed_keys - an array of strings specifying individual named keys the user may access

A successful request must set `allow`, `sub` and either `roles` or `allowed_keys` depending on the desired auth model.

A key can be used if the key's name is listed in `allowed_keys`, or there is an intersection between the `roles` response and the `roles` in the key's configuration in the relic server configuration, or both.

## Interactive authentication

A server with OPA enabled may provide metadata that allows the client to interactively
authenticate to Azure AD and then provide the resulting token to relic.

To enable this, first create or update an Azure AD application with the following
under the "Authentication" tab:

- In the "Mobile and desktop applications" box, add `http://localhost` as a permitted Redirect URI.
- In the "Advanced settings" box, ensure "Allow public client flows" is enabled

Then in the relic server configuration add:

```yaml
server:
  azuread:
    authority: https://login.microsoftonline.com/YOUR-TENANT-ID
    clientid: YOUR-APP-CLIENT-ID
```

You can find the tenant ID and client ID on the "Overview" tab of your app registration.
The full authority URL can be found by clicking the "Endpoints" button at the top
and removing everything after the tenant ID from any of the displayed OAuth URLs.

Finally, to configure a client to use interactive auth run:

    relic remote login -u https://relic.example.com

## Verifying OpenID Connect tokens

To get started with writing a policy that can verify OpenID Connect tokens
such as those from interactive command-line login,
see [the OPA documentation](https://www.openpolicyagent.org/docs/latest/oauth-oidc/).
