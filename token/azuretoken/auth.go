package azuretoken

import (
	"errors"
	"os"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/sassoftware/relic/v8/config"
)

var compatVars = map[string]string{
	"AZURE_BEARER_TOKEN_FILE":    "AZURE_FEDERATED_TOKEN_FILE",
	"AZURE_CERTIFICATE_PATH":     "AZURE_CLIENT_CERTIFICATE_PATH",
	"AZURE_CERTIFICATE_PASSWORD": "AZURE_CLIENT_CERTIFICATE_PASSWORD",
}

func newCredential(tconf *config.TokenConfig) (azcore.TokenCredential, error) {
	// backwards compat with autorest
	for oldName, newName := range compatVars {
		value := os.Getenv(oldName)
		if value != "" && os.Getenv(newName) == "" {
			os.Setenv(newName, value)
		}
	}

	switch {
	case tconf.Pin == nil:
		// use default (environment)
		return azidentity.NewDefaultAzureCredential(nil)

	case *tconf.Pin == "":
		// PIN present but empty means use azure CLI auth
		opts := &azidentity.AzureCLICredentialOptions{}
		if os.Getenv("AZURE_ADDITIONALLY_ALLOWED_TENANTS") == "" {
			opts.AdditionallyAllowedTenants = []string{"*"}
		}
		return azidentity.NewAzureCLICredential(opts)

	default:
		return nil, errors.New("azure token pin must be empty or absent - credential files are no longer supported")
	}
}
