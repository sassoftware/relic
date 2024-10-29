# Using Relic with Azure Key Vault

Relic can use keys and certificates stored in an Azure Key Vault to sign.

## Keys

Relic can use either certificates or keys not associated with a certificate.
If a key is used, the ID of a single key version must be provided.
For a certificate, the ID may be provided with or without a version.
In the latter case, the latest version will be selected and cached
until relic is reloaded.

For example, these are all valid key configurations:

```yaml
id: https://example.vault.azure.net/keys/my-azure-key/00112233445566778899aabbccddeeff
id: https://example.vault.azure.net/certificates/my-azure-key
id: https://example.vault.azure.net/certificates/my-azure-key/00112233445566778899aabbccddeeff
```

If a certificate ID is provided and `x509certificate` is not set,
then the certificate will be loaded from Azure Key Vault.

Relic does not yet support generating or importing keys or certificates into Azure.

## Authentication

Authenticating to Azure can be accomplished in all the usual ways.
This includes using secrets, certificates, managed service identity,
the Azure CLI, or via a federated identity token.

These can all be configured using the standard environment variables per the
[SDK documentation](https://learn.microsoft.com/en-us/azure/developer/go/azure-sdk-authentication).

Azure CLI auth is enabled by default, but may require additional configuration
to set the allowed tenant ID(s).
CLI auth that allows all tenants can be forced by setting an empty PIN:

```yaml
tokens:
  azure:
    type: azure
    pin: ""
```

In a Kubernetes or GitHub Actions environment, use of
[Workload Identity Federation](https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation)
is strongly recommended.
