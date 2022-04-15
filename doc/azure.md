# Using Relic with Azure Key Vault

Relic can use keys and certificates stored in an Azure Key Vault to sign.

## Keys

Relic can use either certificates or keys not associated with a certificate.
If a key is used, the ID of a single key version must be provided.
For a certificate, the ID may be provided with or without a version.
In the latter case, the latest version will be selected and cached until relic is reloaded.

For example, these are all valid key configurations:

```yaml
id: https://example.vault.azure.net/keys/my-azure-key/00112233445566778899aabbccddeeff
id: https://example.vault.azure.net/certificates/my-azure-key
id: https://example.vault.azure.net/certificates/my-azure-key/00112233445566778899aabbccddeeff
```

If a certificate ID is provided and `x509certificate` is not set, then the certificate will be loaded from Azure Key Vault.

Relic does not yet support generating or importing keys or certificates into Azure.

## Authentication

Authenticating to Azure can be accomplished in all the usual ways.
This includes using secrets, certificates, managed service identity, the Azure CLI, or via a federated identity token.

If no explicit configuration is provided to relic then azure will be configured via the process environment.
The default set of accepted environment variables can be found [here](https://pkg.go.dev/github.com/Azure/go-autorest/autorest/azure/auth#pkg-constants).

For interactive use, configuring relic to use Azure CLI auth is convenient.
Setting pin to an empty string will enable this:

```yaml
tokens:
  azure:
    type: azure
    pin: ""
```

If modifying the environment is not desireable, or more than one account is to be used, the pin option can be used to point to a JSON file with credentials or other azure-sdk settings:

```yaml
tokens:
  azure:
    type: azure
    pin: /etc/relic/mycred.json
```

Finally, in a Kubernetes or GitHub Actions environment, a native service token can be used to authenticate using Workload Identity Federation.
To use this, set `AZURE_BEARER_TOKEN_FILE` to a file containing the token, and also set `AZURE_CLIENT_ID` and `AZURE_TENANT_ID` to their respective values.
See the [workload identity federation doc](https://docs.microsoft.com/en-us/azure/active-directory/develop/workload-identity-federation) for more details.