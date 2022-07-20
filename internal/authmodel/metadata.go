package authmodel

type AuthType string

const (
	AuthTypeCertificate AuthType = "https://relic.sas.com/auth/certificate"
	AuthTypeBearerToken AuthType = "https://relic.sas.com/auth/bearer-token"
	AuthTypeAzureAD     AuthType = "https://relic.sas.com/auth/azure-ad"
)

type Metadata struct {
	Hosts []string       `json:"hosts"`
	Auth  []AuthMetadata `json:"auth"`
}

type AuthMetadata struct {
	Type AuthType `json:"type"`
	// azure AD
	Authority string   `json:"authority,omitempty"`
	ClientID  string   `json:"client_id,omitempty"`
	Scopes    []string `json:"scopes,omitempty"`
}
