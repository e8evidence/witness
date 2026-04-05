package witness

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

var graphBaseURL = "https://graph.microsoft.com/v1.0"

// patchAgeLimitWorkstation is the maximum age since last OS patch for ML2.
// ASD ISM-1876: OS patches applied within 2 weeks for workstations.
const patchAgeLimitWorkstation = 14 * 24 * time.Hour

// Well-known Entra ID role template IDs for privileged role auditing (ISM-1507).
var privilegedRoleIDs = []string{
	"62e90394-69f5-4237-9190-012177145e10", // Global Administrator
	"e8611ab8-c189-46e8-94e1-60213ab1f814", // Privileged Role Administrator
	"194ae4cb-b126-40b2-bd5b-6091b380977d", // Security Administrator
	"29232cdf-9323-42fd-ade2-1d097af3e4de", // Exchange Administrator
}

// MSGraphClient audits a Microsoft 365 tenant via Microsoft Graph.
type MSGraphClient struct {
	httpClient *http.Client
	log        *slog.Logger
	token      string
	tenantID   string
}

// NewMSGraphClient returns a ready-to-use client.
//
// creds.AccessToken must be pre-populated by the caller (e.g. via a
// GraphClientFactory OBO or client-credentials flow). The legacy refresh-token
// exchange path is not supported.
//
// ctx is accepted for API symmetry with NewGoogleWorkspaceClient; Microsoft
// Graph clients use a pre-supplied access token and perform no I/O during
// construction.
func NewMSGraphClient(_ context.Context, creds MicrosoftCredentials, log *slog.Logger) (*MSGraphClient, error) {
	if creds.AccessToken == "" {
		return nil, fmt.Errorf(
			"MSGraphClient: AccessToken is empty — " +
				"obtain a token externally before constructing this client",
		)
	}
	return &MSGraphClient{
		httpClient: &http.Client{Timeout: 30 * time.Second},
		log:        log,
		token:      creds.AccessToken,
		tenantID:   creds.TenantID,
	}, nil
}

// AuditMFA fetches authentication methods for every user and flags those
// without FIDO2 or Windows Hello — required for ML2 per ISM-1504 / ISM-1679.
func (c *MSGraphClient) AuditMFA(ctx context.Context) (StrategyResult, error) {
	users, err := c.listUsers(ctx)
	if err != nil {
		return StrategyResult{}, fmt.Errorf("AuditMFA: list users: %w", err)
	}

	findings := make([]Finding, 0, len(users))
	for _, u := range users {
		methods, err := c.authMethods(ctx, u.ID)
		if err != nil {
			c.log.Warn("AuditMFA: skip user", "user_hash", HashPII(u.UserPrincipalName), "err", err)
			continue
		}

		hasStrong := hasStrongMethod(methods)
		evidence, _ := json.Marshal(methods)

		findings = append(findings, Finding{
			UserHash:    HashPII(u.UserPrincipalName),
			Description: strongMethodDescription(hasStrong),
			Control:     "ISM-1504",
			Passed:      hasStrong,
			Evidence:    string(evidence),
		})
	}

	return BuildStrategyResult(StrategyMFA, findings), nil
}

// AuditPatching queries Intune managedDevices and checks OS patch currency
// per ISM-1876 (OS patches within 2 weeks for workstations).
func (c *MSGraphClient) AuditPatching(ctx context.Context) (StrategyResult, error) {
	devices, err := c.listManagedDevices(ctx)
	if err != nil {
		return StrategyResult{}, fmt.Errorf("AuditPatching: list devices: %w", err)
	}

	findings := make([]Finding, 0, len(devices))
	cutoff := time.Now().UTC().Add(-patchAgeLimitWorkstation)

	for _, d := range devices {
		lastSync, _ := time.Parse(time.RFC3339, d.LastSyncDateTime)
		compliant := lastSync.After(cutoff)

		evidence, _ := json.Marshal(map[string]string{
			"osVersion":        d.OSVersion,
			"lastSyncDateTime": d.LastSyncDateTime,
		})

		findings = append(findings, Finding{
			UserHash:    HashPII(d.ID), // hash device ID, not user
			Description: fmt.Sprintf("OS %s — last sync %s", d.OSVersion, d.LastSyncDateTime),
			Control:     "ISM-1876",
			Passed:      compliant,
			Evidence:    string(evidence),
		})
	}

	return BuildStrategyResult(StrategyPatchOS, findings), nil
}

// AuditAdminRoles lists members of privileged Entra ID roles and checks that
// each has phishing-resistant MFA — required for ML2 per ISM-1507 / ISM-1175.
//
// Roles audited: Global Administrator, Privileged Role Administrator,
// Security Administrator, Exchange Administrator.
//
// Required app role: RoleManagement.Read.Directory
func (c *MSGraphClient) AuditAdminRoles(ctx context.Context) (StrategyResult, error) {
	// Collect unique privileged principals across all targeted roles.
	seen := make(map[string]bool)
	var admins []msUser

	for _, roleID := range privilegedRoleIDs {
		path := fmt.Sprintf(
			"/roleManagement/directory/roleAssignments"+
				"?$filter=roleDefinitionId eq '%s'"+
				"&$expand=principal($select=id,userPrincipalName)",
			roleID,
		)
		var page msRoleAssignmentList
		if err := c.graphGet(ctx, path, &page); err != nil {
			c.log.Warn("AuditAdminRoles: skip role", "role_id", roleID, "err", err)
			continue
		}
		for _, ra := range page.Value {
			if ra.Principal == nil || seen[ra.PrincipalID] {
				continue
			}
			seen[ra.PrincipalID] = true
			admins = append(admins, *ra.Principal)
		}
	}

	findings := make([]Finding, 0, len(admins))
	for _, u := range admins {
		methods, err := c.authMethods(ctx, u.ID)
		if err != nil {
			c.log.Warn("AuditAdminRoles: skip admin", "user_hash", HashPII(u.UserPrincipalName), "err", err)
			continue
		}
		hasStrong := hasStrongMethod(methods)
		evidence, _ := json.Marshal(map[string]any{"mfa_methods": methods})
		findings = append(findings, Finding{
			UserHash:    HashPII(u.UserPrincipalName),
			Description: adminMFADescription(hasStrong),
			Control:     "ISM-1507",
			Passed:      hasStrong,
			Evidence:    string(evidence),
		})
	}

	return BuildStrategyResult(StrategyRestrictAdmin, findings), nil
}

// --- Graph API helpers ----------------------------------------------------

type msUser struct {
	ID                string `json:"id"`
	UserPrincipalName string `json:"userPrincipalName"`
}

type msUserList struct {
	Value    []msUser `json:"value"`
	NextLink string   `json:"@odata.nextLink,omitempty"`
}

type msAuthMethod struct {
	ODataType string `json:"@odata.type"`
}

type msDevice struct {
	ID               string `json:"id"`
	OSVersion        string `json:"osVersion"`
	LastSyncDateTime string `json:"lastSyncDateTime"`
}

type msDeviceList struct {
	Value    []msDevice `json:"value"`
	NextLink string     `json:"@odata.nextLink,omitempty"`
}

type msRoleAssignment struct {
	PrincipalID string  `json:"principalId"`
	Principal   *msUser `json:"principal"` // expanded via $expand=principal
}

type msRoleAssignmentList struct {
	Value []msRoleAssignment `json:"value"`
}

func (c *MSGraphClient) listUsers(ctx context.Context) ([]msUser, error) {
	var all []msUser
	path := "/users?$select=id,userPrincipalName&$top=999"
	for path != "" {
		var page msUserList
		if err := c.graphGet(ctx, path, &page); err != nil {
			return nil, err
		}
		all = append(all, page.Value...)
		path = strings.TrimPrefix(page.NextLink, graphBaseURL)
	}
	return all, nil
}

func (c *MSGraphClient) authMethods(ctx context.Context, userID string) ([]msAuthMethod, error) {
	type list struct {
		Value []msAuthMethod `json:"value"`
	}
	var result list
	path := fmt.Sprintf("/users/%s/authentication/methods", userID)
	if err := c.graphGet(ctx, path, &result); err != nil {
		return nil, err
	}
	return result.Value, nil
}

func (c *MSGraphClient) listManagedDevices(ctx context.Context) ([]msDevice, error) {
	var all []msDevice
	path := "/deviceManagement/managedDevices?$select=id,osVersion,lastSyncDateTime&$top=999"
	for path != "" {
		var page msDeviceList
		if err := c.graphGet(ctx, path, &page); err != nil {
			return nil, err
		}
		all = append(all, page.Value...)
		path = strings.TrimPrefix(page.NextLink, graphBaseURL)
	}
	return all, nil
}

// graphGet performs an authenticated GET and decodes JSON into dest.
// Returns typed errors for consent/permission failures so the worker can
// update the tenant's consent status in the database.
func (c *MSGraphClient) graphGet(ctx context.Context, path string, dest any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, graphBaseURL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("ConsistencyLevel", "eventual")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("graph GET %s: %w", path, err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	switch resp.StatusCode {
	case http.StatusOK:
		return json.Unmarshal(body, dest)

	case http.StatusUnauthorized:
		// 401 with application credentials means the token was rejected —
		// typically because admin consent was never granted or the service
		// principal was deleted from the customer tenant.
		return &ConsentRevokedError{TenantID: c.tenantID, StatusCode: http.StatusUnauthorized}

	case http.StatusForbidden:
		// 403 with claims=: Continuous Access Evaluation step-up challenge (2026+).
		if cc := resp.Header.Get("WWW-Authenticate"); strings.Contains(cc, "claims=") {
			return &ClaimsChallengeError{Path: path, Challenge: cc}
		}
		// 403 without claims=: app role not assigned — consent was revoked or
		// the required application permission was removed in the customer tenant.
		return &ConsentRevokedError{TenantID: c.tenantID, StatusCode: http.StatusForbidden}

	default:
		return fmt.Errorf("graph GET %s: HTTP %d: %s", path, resp.StatusCode, body)
	}
}

// --- helpers ---------------------------------------------------------------

// strongMFATypes are the methods that satisfy ML2 under ISM-1504.
// FIDO2 / Windows Hello = phishing-resistant.
var strongMFATypes = map[string]bool{
	"#microsoft.graph.fido2AuthenticationMethod":                   true,
	"#microsoft.graph.windowsHelloForBusinessAuthenticationMethod": true,
}

func hasStrongMethod(methods []msAuthMethod) bool {
	for _, m := range methods {
		if strongMFATypes[m.ODataType] {
			return true
		}
	}
	return false
}

func strongMethodDescription(ok bool) string {
	if ok {
		return "User has phishing-resistant MFA (FIDO2 or Windows Hello)"
	}
	return "User lacks phishing-resistant MFA — FIDO2/Windows Hello required for ML2 (ISM-1504)"
}

func adminMFADescription(ok bool) string {
	if ok {
		return "Privileged account uses phishing-resistant MFA (FIDO2 or Windows Hello)"
	}
	return "Privileged account lacks phishing-resistant MFA — required for ML2 (ISM-1507)"
}
