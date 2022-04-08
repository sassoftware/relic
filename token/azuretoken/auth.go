package azuretoken

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"os"

	kvauth "github.com/Azure/azure-sdk-for-go/services/keyvault/auth"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	"github.com/sassoftware/relic/v7/config"
)

// Configure azure authentication based on the token config and/or process
// environment.
func newAuthorizer(tconf *config.TokenConfig) (autorest.Authorizer, error) {
	if tconf.Pin == nil {
		// PIN not present means use environment
		return newAuthorizerFromEnvironment()
	}
	credFile := *tconf.Pin
	if credFile == "" {
		// PIN present but empty means use azure CLI auth
		return kvauth.NewAuthorizerFromCLI()
	}
	// PIN is path to a file with credentials and settings
	os.Setenv("AZURE_AUTH_LOCATION", credFile)
	return kvauth.NewAuthorizerFromFile()
}

// If AZURE_BEARER_TOKEN_FILE is set then auth using that file, otherwise follow
// the same route as keyvault/auth.
//
// The bearer token case looks something like this:
// https://docs.microsoft.com/en-us/azure/active-directory/develop/workload-identity-federation-create-trust-gcp?tabs=typescript#exchange-a-google-token-for-an-access-token
func newAuthorizerFromEnvironment() (autorest.Authorizer, error) {
	// parse settings from environment
	resource, err := getResource()
	if err != nil {
		return nil, fmt.Errorf("AZURE_ENVIRONMENT: %w", err)
	}
	settings, err := auth.GetSettingsFromEnvironment()
	if err != nil {
		return nil, fmt.Errorf("parsing environment: %w", err)
	}
	settings.Values[auth.Resource] = resource

	// read bearer token from file
	tokenFile := os.Getenv("AZURE_BEARER_TOKEN_FILE")
	if tokenFile == "" {
		// MSI or other env auth
		return settings.GetAuthorizer()
	}
	clientID := settings.Values[auth.ClientID]
	tenantID := settings.Values[auth.TenantID]
	if clientID == "" || tenantID == "" {
		return nil, errors.New("AZURE_CLIENT_ID and AZURE_TENANT_ID are required")
	}

	secret := &bearerTokenFileSecret{tokenFile: tokenFile}
	oauthConf, err := adal.NewOAuthConfig(settings.Environment.ActiveDirectoryEndpoint, tenantID)
	if err != nil {
		return nil, fmt.Errorf("ADAL.NewOAuthConfig: %w", err)
	}
	spt, err := adal.NewServicePrincipalTokenWithSecret(*oauthConf, clientID, resource, secret)
	if err != nil {
		return nil, fmt.Errorf("configuring service principal: %w", err)
	}
	return autorest.NewBearerAuthorizer(spt), nil
}

// copied from keyvault/auth
func getResource() (string, error) {
	var env azure.Environment

	if envName := os.Getenv("AZURE_ENVIRONMENT"); envName == "" {
		env = azure.PublicCloud
	} else {
		var err error
		env, err = azure.EnvironmentFromName(envName)
		if err != nil {
			return "", err
		}
	}

	resource := os.Getenv("AZURE_KEYVAULT_RESOURCE")
	if resource == "" {
		resource = env.ResourceIdentifiers.KeyVault
	}

	return resource, nil
}

type bearerTokenFileSecret struct {
	tokenFile string
}

func (b *bearerTokenFileSecret) SetAuthenticationValues(spt *adal.ServicePrincipalToken, v *url.Values) error {
	blob, err := os.ReadFile(b.tokenFile)
	if err != nil {
		return err
	}
	bearerToken := string(bytes.TrimSpace(blob))

	v.Set("client_assertion", bearerToken)
	v.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	return nil
}

// MarshalJSON implements the json.Marshaler interface.
func (bearerTokenFileSecret) MarshalJSON() ([]byte, error) {
	return nil, errors.New("not implemented")
}
