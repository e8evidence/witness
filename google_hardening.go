package witness

// Strategy #4: User Application Hardening — Google Workspace implementation.
//
// # What this audits
//
// Three independent check groups, each contributing findings:
//
//  1. CBCM stable-channel check (ISM-1486): Chrome Browser Cloud Management
//     enrollment + all managed browsers on the stable release channel.
//     If CBCM is not enrolled, a single failing finding is emitted instead
//     (browser hardening policies cannot be enforced without central management).
//
//  2. Chrome policy resolution (ISM-1485, ISM-1486): Safe Browsing and Site
//     Isolation policy state, resolved via the Chrome Management Policy API.
//     Requires an org unit ID, which is obtained from the Admin SDK orgunits
//     list.  Skipped silently when the domain has a flat (root-only) org
//     structure because the Admin SDK does not surface the root OU's ID.
//
//  3. High-risk OAuth grant scan (ISM-1486): scans admin users and a sample of
//     regular users for OAuth tokens with scopes that enable email exfiltration
//     or impersonation (gmail.send, gmail.modify, full Gmail, admin.directory).
//     Runs regardless of CBCM enrollment status.
//
// # What this does NOT audit (and why)
//
//   - "Trust domain-owned apps only" for Apps Script: no REST endpoint exists.
//   - "Third-party app access" toggle in Security > API Controls: no REST endpoint.
//   - Java / Flash plugin enforcement: Flash is end-of-life; Chrome removed
//     NPAPI in 2015. Checking "legacy plugin" policies has no security value.
//   - WebAssembly restriction: not an explicit ISM control requirement and
//     restricting WASM breaks many legitimate business web apps.
//   - Password Manager forced-off: ISM does not require disabling Chrome's
//     built-in password manager; ML2/ML3 hardening focuses on extension control
//     and phishing-resistant MFA, not password manager brand preference.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// hardeningHighRiskScopes are OAuth scopes that enable email exfiltration or
// impersonation and should be flagged when granted to non-essential apps.
var hardeningHighRiskScopes = map[string]bool{
	"https://mail.google.com/":                              true, // full Gmail (IMAP-level)
	"https://www.googleapis.com/auth/gmail.send":            true, // send email as user
	"https://www.googleapis.com/auth/gmail.modify":          true, // read, compose, send, delete
	"https://www.googleapis.com/auth/gmail.compose":         true, // compose and send
	"https://www.googleapis.com/auth/admin.directory.user":  true, // manage all users
	"https://www.googleapis.com/auth/admin.directory.group": true, // manage groups
}

// --- org unit helpers ------------------------------------------------------

type orgUnit struct {
	OrgUnitID   string `json:"orgUnitId"`
	Name        string `json:"name"`
	OrgUnitPath string `json:"orgUnitPath"`
}

type orgUnitList struct {
	OrganizationUnits []orgUnit `json:"organizationUnits"`
}

// listOrgUnits returns all org units in the domain (children of root).
// An empty slice means the domain has only the root OU, whose ID the Admin
// SDK does not expose directly.
func (c *GoogleWorkspaceClient) listOrgUnits(ctx context.Context) ([]orgUnit, error) {
	path := fmt.Sprintf("/customer/%s/orgunits?type=ALL", c.customerID)
	var result orgUnitList
	if err := c.adminGet(ctx, path, &result); err != nil {
		return nil, err
	}
	return result.OrganizationUnits, nil
}

// --- Chrome Management Policy API helpers ----------------------------------

type chromePolicyTargetKey struct {
	TargetResource string `json:"targetResource"`
}

type chromePolicyResolveRequest struct {
	PolicyTargetKey    chromePolicyTargetKey `json:"policyTargetKey"`
	PolicySchemaFilter string                `json:"policySchemaFilter"`
	PageSize           int                   `json:"pageSize,omitempty"`
}

type chromePolicySettings struct {
	PolicySchema string         `json:"policySchema"`
	Settings     map[string]any `json:"value"`
}

type chromePolicyResolved struct {
	Policy chromePolicySettings `json:"value"`
}

type chromePolicyResolveResponse struct {
	ResolvedPolicies []chromePolicyResolved `json:"resolvedPolicies"`
}

// resolveChromePolicyRaw calls the Chrome Management Policy API for a given
// org unit and schema, returning the raw response. Returns (nil, nil) when
// the policy is not explicitly set.
func (c *GoogleWorkspaceClient) resolveChromePolicyRaw(
	ctx context.Context, ouID, schema string,
) (*chromePolicyResolveResponse, error) {
	reqBody := chromePolicyResolveRequest{
		PolicyTargetKey: chromePolicyTargetKey{
			TargetResource: "orgunits/" + ouID,
		},
		PolicySchemaFilter: schema,
		PageSize:           5,
	}
	b, _ := json.Marshal(reqBody)

	endpoint := fmt.Sprintf("%s/customers/%s/policies:resolve", chromeMgmtBase, c.customerID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("chrome policy resolve %s: %w", schema, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("chrome policy resolve %s: HTTP %d: %s", schema, resp.StatusCode, body)
	}

	var result chromePolicyResolveResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("chrome policy resolve %s: decode: %w", schema, err)
	}
	if len(result.ResolvedPolicies) == 0 {
		return nil, nil // policy not explicitly set
	}
	return &result, nil
}

// resolveChromePolicyBool resolves a single boolean Chrome policy for the
// given org unit. Returns (false, nil) when the policy is not explicitly set.
func (c *GoogleWorkspaceClient) resolveChromePolicyBool(
	ctx context.Context, ouID, schema, valueKey string,
) (bool, error) {
	result, err := c.resolveChromePolicyRaw(ctx, ouID, schema)
	if err != nil || result == nil {
		return false, err
	}
	v, ok := result.ResolvedPolicies[0].Policy.Settings[valueKey]
	if !ok {
		return false, nil
	}
	boolVal, _ := v.(bool)
	return boolVal, nil
}

// auditChromeHardeningPolicies resolves Safe Browsing and Site Isolation
// Chrome policies for the first available org unit.
// Returns (nil, error) when policy resolution is unavailable (flat OU
// structure or API error) so the caller can skip these findings cleanly.
func (c *GoogleWorkspaceClient) auditChromeHardeningPolicies(ctx context.Context, ous []orgUnit) ([]Finding, error) {
	if len(ous) == 0 {
		return nil, fmt.Errorf("auditChromeHardeningPolicies: root-only OU structure — " +
			"Admin SDK does not expose root OU ID; Chrome policy resolution unavailable")
	}
	ouID := strings.TrimPrefix(ous[0].OrgUnitID, "id:")

	var findings []Finding

	// Safe Browsing (ISM-1486: protect users from known malicious sites)
	safeBrowsing, sbErr := c.resolveChromePolicyBool(
		ctx, ouID, "chrome.users.SafeBrowsingEnabled", "safeBrowsingEnabled",
	)
	if sbErr != nil {
		c.log.Info("auditChromeHardeningPolicies: Safe Browsing check failed", "err", sbErr)
	} else {
		ev, _ := json.Marshal(map[string]any{
			"policySchema":        "chrome.users.SafeBrowsingEnabled",
			"safeBrowsingEnabled": safeBrowsing,
			"orgUnit":             ous[0].OrgUnitPath,
		})
		findings = append(findings, Finding{
			Description: safeBrowsingDescription(safeBrowsing),
			Control:     "ISM-1486",
			Passed:      safeBrowsing,
			Evidence:    string(ev),
		})
	}

	// Site Isolation / Site Per Process (ISM-1485: prevent cross-site data leakage)
	siteIsolation, siErr := c.resolveChromePolicyBool(
		ctx, ouID, "chrome.users.SitePerProcess", "sitePerProcessEnabled",
	)
	if siErr != nil {
		c.log.Info("auditChromeHardeningPolicies: Site Isolation check failed", "err", siErr)
	} else {
		ev, _ := json.Marshal(map[string]any{
			"policySchema":          "chrome.users.SitePerProcess",
			"sitePerProcessEnabled": siteIsolation,
			"orgUnit":               ous[0].OrgUnitPath,
		})
		findings = append(findings, Finding{
			Description: siteIsolationDescription(siteIsolation),
			Control:     "ISM-1485",
			Passed:      siteIsolation,
			Evidence:    string(ev),
		})
	}

	return findings, nil
}

func safeBrowsingDescription(enabled bool) string {
	if enabled {
		return "Chrome Safe Browsing enforced via policy — phishing and malware protection active"
	}
	return "Chrome Safe Browsing NOT enforced via policy — users may access known-malicious sites"
}

func siteIsolationDescription(enabled bool) string {
	if enabled {
		return "Chrome Site Isolation (SitePerProcess) enforced via policy — cross-site data leakage mitigated"
	}
	return "Chrome Site Isolation NOT enforced via policy — Spectre/cross-site data leakage risk elevated"
}

// --- High-risk OAuth scope audit ------------------------------------------

// auditHighRiskOAuthGrants scans admin users and a sample of regular users
// for OAuth tokens with scopes that enable email exfiltration or impersonation.
func (c *GoogleWorkspaceClient) auditHighRiskOAuthGrants(ctx context.Context) ([]Finding, error) {
	admins, err := c.listSuperAdmins(ctx)
	if err != nil {
		return nil, fmt.Errorf("auditHighRiskOAuthGrants: list admins: %w", err)
	}

	regularPath := fmt.Sprintf("/users?customer=%s&maxResults=20&projection=basic", c.customerID)
	var regularList gsuiteUserList
	_ = c.adminGet(ctx, regularPath, &regularList)

	users := collectUsersToScan(admins, regularList.Users)
	var findings []Finding
	for _, u := range users {
		tokens, err := c.listUserTokens(ctx, u.PrimaryEmail)
		if err != nil {
			c.log.Warn("auditHighRiskOAuthGrants: list tokens", "user", HashPII(u.PrimaryEmail), "err", err)
			continue
		}
		for _, tok := range tokens {
			scope := firstHighRiskScope(tok.Scopes)
			if scope == "" {
				continue
			}
			ev, _ := json.Marshal(map[string]string{
				"app":           tok.DisplayText,
				"highRiskScope": scope,
				"clientId":      tok.ClientID,
			})
			findings = append(findings, Finding{
				UserHash: HashPII(u.PrimaryEmail),
				Description: fmt.Sprintf(
					"App '%s' holds high-risk scope '%s' — review whether this grant is authorised",
					tok.DisplayText, friendlyScopeName(scope),
				),
				Control:  "ISM-1486",
				Passed:   false,
				Evidence: string(ev),
			})
		}
	}

	// A single passing finding when no high-risk grants are found keeps the
	// OAuth check visible in the findings list rather than silently absent.
	if len(findings) == 0 {
		ev, _ := json.Marshal(map[string]any{
			"usersScanned":        len(users),
			"highRiskGrantsFound": 0,
		})
		findings = append(findings, Finding{
			Description: fmt.Sprintf(
				"No high-risk OAuth grants (gmail.send / full Gmail / admin.directory) detected across %d scanned users",
				len(users),
			),
			Control:  "ISM-1486",
			Passed:   true,
			Evidence: string(ev),
		})
	}

	return findings, nil
}

func firstHighRiskScope(scopes []string) string {
	for _, s := range scopes {
		if hardeningHighRiskScopes[s] {
			return s
		}
	}
	return ""
}

var scopeFriendlyNames = map[string]string{
	"https://mail.google.com/":                              "full Gmail access",
	"https://www.googleapis.com/auth/gmail.send":            "send email as user",
	"https://www.googleapis.com/auth/gmail.modify":          "read/compose/send/delete email",
	"https://www.googleapis.com/auth/gmail.compose":         "compose and send email",
	"https://www.googleapis.com/auth/admin.directory.user":  "manage all users",
	"https://www.googleapis.com/auth/admin.directory.group": "manage groups",
}

func friendlyScopeName(scope string) string {
	if name, ok := scopeFriendlyNames[scope]; ok {
		return name
	}
	return scope
}

// --- AuditUserAppHardening (main entry point) ------------------------------

// AuditUserAppHardening audits Strategy #4 for Google Workspace tenants.
// It always returns findings (never ErrNotAuditable) because the OAuth grant
// scan runs regardless of CBCM enrollment status.
func (c *GoogleWorkspaceClient) AuditUserAppHardening(ctx context.Context) (StrategyResult, error) {
	var findings []Finding

	// Part 1: CBCM enrollment + stable-channel check (ISM-1486).
	versions, cbcmErr := c.listManagedBrowserVersions(ctx)
	if cbcmErr != nil && !errors.Is(cbcmErr, ErrNotAuditable) {
		return StrategyResult{}, fmt.Errorf("AuditUserAppHardening: CBCM: %w", cbcmErr)
	}
	cbcmEnrolled := !errors.Is(cbcmErr, ErrNotAuditable)

	if cbcmEnrolled {
		// Emit one finding per (version, channel, system) group.
		// Channel comes from the API as uppercase "STABLE" | "BETA" | "DEV" | "CANARY".
		for _, v := range versions {
			onStable := v.Channel == "STABLE"
			ev, _ := json.Marshal(map[string]any{
				"channel": v.Channel,
				"system":  v.System,
				"version": v.Version,
				"count":   v.Count,
			})
			findings = append(findings, Finding{
				Description: fmt.Sprintf(
					"%d %s Chrome browser(s) on v%s (%s channel) — %s",
					v.Count, v.System, v.Version, v.Channel,
					channelComplianceDesc(onStable, v.Channel),
				),
				Control:  "ISM-1486",
				Passed:   onStable,
				Evidence: string(ev),
			})
		}
		if len(versions) == 0 {
			findings = append(findings, Finding{
				Description: "Chrome Browser Cloud Management enrolled but no browsers registered yet",
				Control:     "ISM-1486",
				Passed:      false,
				Evidence:    `{"cbcmEnrolled":true,"managedBrowsers":0}`,
			})
		}

		// Part 2: Chrome policy checks — Safe Browsing + Site Isolation.
		// Silently skipped when the domain has a flat (root-only) OU structure.
		ous, ouErr := c.listOrgUnits(ctx)
		if ouErr != nil {
			c.log.Info("AuditUserAppHardening: list org units failed", "err", ouErr)
		} else {
			policyFindings, err := c.auditChromeHardeningPolicies(ctx, ous)
			if err != nil {
				c.log.Info("AuditUserAppHardening: Chrome policy check unavailable", "err", err)
			} else {
				findings = append(findings, policyFindings...)
			}
		}
	} else {
		// CBCM not enrolled — browser hardening cannot be centrally enforced.
		findings = append(findings, Finding{
			Description: "Chrome Browser Cloud Management not enrolled — " +
				"browser hardening policies (Safe Browsing, Site Isolation) cannot be enforced or verified centrally",
			Control:  "ISM-1486",
			Passed:   false,
			Evidence: `{"cbcmEnrolled":false}`,
		})
	}

	// Part 3: High-risk OAuth grant scan (always runs).
	oauthFindings, err := c.auditHighRiskOAuthGrants(ctx)
	if err != nil {
		c.log.Warn("AuditUserAppHardening: OAuth scan failed", "err", err)
	} else {
		findings = append(findings, oauthFindings...)
	}

	return BuildStrategyResult(StrategyUserAppHardening, findings), nil
}

// channelComplianceDesc returns a short compliance description for a Chrome channel.
func channelComplianceDesc(onStable bool, channel string) string {
	if onStable {
		return "stable channel — compliant"
	}
	return fmt.Sprintf("%s channel — non-production channels receive unvetted updates and are non-compliant per ISM-1486", channel)
}
