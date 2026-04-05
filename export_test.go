package witness

import (
	"io"
	"log/slog"
	"net/http"
)

// Test-only constructors that bypass credential validation and token exchange.

func NewGoogleWorkspaceClientForTest(hc *http.Client, token, customerID string) *GoogleWorkspaceClient {
	return &GoogleWorkspaceClient{
		httpClient: hc,
		log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		token:      token,
		customerID: customerID,
	}
}

func NewMSGraphClientForTest(hc *http.Client, token, tenantID string) *MSGraphClient {
	return &MSGraphClient{
		httpClient: hc,
		log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		token:      token,
		tenantID:   tenantID,
	}
}

// Pointers to package-level URL vars so tests can override and restore them.
var (
	AdminSDKBaseVar   = &adminSDKBase
	ChromeMgmtBaseVar = &chromeMgmtBase
	VaultBaseVar      = &vaultBase
	GoogleTokenURLVar = &googleTokenURL
	GraphBaseURLVar   = &graphBaseURL
)
