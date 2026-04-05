package witness

// GoogleCredentials holds OAuth2 tokens for a Google Workspace tenant.
//
// For direct mode these are populated by decrypting the tenant credentials
// file. When AccessToken is non-empty (pre-exchanged by a reseller/DWD
// resolver), the refresh-token fields are left empty and no exchange is
// performed.
type GoogleCredentials struct {
	CustomerID   string `json:"customer_id"`
	AdminEmail   string `json:"admin_email"`
	RefreshToken string `json:"refresh_token"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`

	// AccessToken, when set, is used directly and bypasses the refresh-token
	// exchange. Set by the Google Reseller / DWD resolver.
	AccessToken string `json:"access_token,omitempty"`
}

// MicrosoftCredentials holds an OAuth2 access token for a Microsoft 365 tenant.
//
// AccessToken must be pre-populated by the caller (e.g. via a GraphClientFactory
// OBO / client-credentials flow). The legacy refresh-token exchange path is not
// supported; obtain a token externally and pass it here.
type MicrosoftCredentials struct {
	TenantID string `json:"tenant_id"`

	// AccessToken must be set before constructing MSGraphClient.
	AccessToken string `json:"access_token,omitempty"`
}
