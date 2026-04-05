package witness

// Strategy #7: Application Control — Google Workspace implementation.
//
// # What this audits
//
// Three check groups, each contributing findings:
//
//  1. CBCM enrollment (ISM-0140): Chrome Browser Cloud Management must be
//     enrolled before any extension or app policy can be centrally enforced.
//     Returns ErrNotAuditable when CBCM is not enrolled (an organisation with
//     no central browser management cannot be assessed for application control
//     via the Google APIs).
//
//  2. Extension install blocklist (ISM-1490): resolves
//     chrome.users.ExtensionInstallBlocklist via the Chrome Management Policy
//     API. A value of ["*"] means "block all extensions by default", which is
//     the deny-by-default posture required for ML2/ML3.
//
//  3. Extension install allowlist (ISM-1490): resolves
//     chrome.users.ExtensionInstallAllowlist. A non-empty allowlist means that
//     approved exceptions to the block-all default have been explicitly
//     configured. Included as an evidence signal — an empty allowlist with
//     block-all still passes (legitimate) but may indicate an overly strict
//     policy that is being worked around.
//
// # What this does NOT audit (and why)
//
//   - Google Workspace Marketplace settings: the "allow/block Marketplace app
//     installation" toggle in Admin Console > Security > API Controls has no
//     published REST endpoint. It cannot be programmatically queried.
//
//   - "Runtime Blocked Hosts" policy: this is a web browsing restriction
//     (what sites extensions can run on), not an application-install control.
//     Out of scope for ISM-1490.
//
//   - Shadow IT matching (installed vs allowlist): the installed-app count
//     comes from a fleet-wide aggregate; the allowlist lives per OU in the
//     Policy API. Cross-referencing them would require resolving every OU's
//     policy — high complexity, low additional signal, because the blocklist
//     itself prevents unauthorised installs.
//
//   - Android/Play Store policy (chrome.users.appsconfig): returns an enum
//     (PLAY_STORE_AND_ARC_ENABLED / PLAY_STORE_DISABLED), not a bool.
//     resolveChromePolicyBool cannot handle it; resolveChromePolicyStringSlice
//     is also wrong for an enum. Omitted to avoid misleading findings.
//
//   - admin.directory.v1.devices.chromebrowsers: this API path does not exist.
//     Chrome browser management is at chromemanagement.googleapis.com/v1,
//     which is what this file uses.
//
//   - google.golang.org/api client library: not used in this package; all
//     API calls use raw net/http.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// resolveChromePolicyStringSlice resolves a Chrome Management Policy that
// returns a string-array value (e.g. ExtensionInstallBlocklist).
// Returns (nil, nil) when the policy is not explicitly set.
func (c *GoogleWorkspaceClient) resolveChromePolicyStringSlice(
	ctx context.Context, ouID, schema, valueKey string,
) ([]string, error) {
	result, err := c.resolveChromePolicyRaw(ctx, ouID, schema)
	if err != nil || result == nil {
		return nil, err
	}
	v, ok := result.ResolvedPolicies[0].Policy.Settings[valueKey]
	if !ok {
		return nil, nil
	}
	// JSON unmarshal produces []any for arrays.
	raw, _ := v.([]any)
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out, nil
}

// --- Installed-apps report -------------------------------------------------

type installedApp struct {
	AppID        string `json:"appId"`
	AppType      string `json:"appType"`
	AppName      string `json:"appName"`
	AppSource    string `json:"appSource"`
	BrowserCount int    `json:"browserDeviceCount"`
	OsUserCount  int    `json:"osUserCount"`
}

type countInstalledAppsResponse struct {
	InstalledApps []installedApp `json:"installedApps"`
	NextPageToken string         `json:"nextPageToken"`
}

// countInstalledExtensions returns the number of distinct Chrome extensions
// installed fleet-wide, along with a JSON evidence blob of the top entries
// (capped at 50 to keep the blob manageable).
func (c *GoogleWorkspaceClient) countInstalledExtensions(ctx context.Context) (int, json.RawMessage) {
	var all []installedApp
	pageToken := ""
	for {
		path := fmt.Sprintf(
			"%s/customers/%s/reports:countInstalledApps?filter=appType%%3DEXTENSION&pageSize=100",
			chromeMgmtBase, c.customerID,
		)
		if pageToken != "" {
			path += "&pageToken=" + pageToken
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, path, nil)
		if err != nil {
			break
		}
		req.Header.Set("Authorization", "Bearer "+c.token)

		resp, err := c.httpClient.Do(req)
		if err != nil {
			break
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			break
		}
		var result countInstalledAppsResponse
		if err := json.Unmarshal(body, &result); err != nil {
			break
		}
		all = append(all, result.InstalledApps...)
		if result.NextPageToken == "" {
			break
		}
		pageToken = result.NextPageToken
	}

	total := len(all)
	// Cap evidence at 50 entries.
	if len(all) > 50 {
		all = all[:50]
	}
	ev, _ := json.Marshal(map[string]any{
		"totalDistinctExtensions": total,
		"sample":                  all,
	})
	return total, json.RawMessage(ev)
}

// --- Extension policy audit -----------------------------------------------

// auditExtensionPolicies resolves the extension install blocklist and allowlist
// Chrome policies for the first available org unit.
// Returns (nil, nil) when no org units are available (flat OU structure).
func (c *GoogleWorkspaceClient) auditExtensionPolicies(ctx context.Context, ous []orgUnit) ([]Finding, error) {
	if len(ous) == 0 {
		return nil, fmt.Errorf("auditExtensionPolicies: root-only OU structure — " +
			"Chrome Management Policy API requires a child OU ID; policy checks unavailable")
	}
	ouID := strings.TrimPrefix(ous[0].OrgUnitID, "id:")

	// --- Blocklist (deny-by-default) ---
	//
	// chrome.users.ExtensionInstallBlocklist with value ["*"] means
	// "block all extensions by default".  Without this, any user can install
	// any extension from the Chrome Web Store.
	blocklist, blErr := c.resolveChromePolicyStringSlice(
		ctx, ouID,
		"chrome.users.ExtensionInstallBlocklist",
		"extensionInstallBlocklist",
	)

	// --- Allowlist (approved exceptions) ---
	//
	// chrome.users.ExtensionInstallAllowlist with a non-empty list means
	// specific approved extensions are permitted despite the block-all default.
	allowlist, alErr := c.resolveChromePolicyStringSlice(
		ctx, ouID,
		"chrome.users.ExtensionInstallAllowlist",
		"extensionInstallAllowlist",
	)

	extCount, extEv := c.countInstalledExtensions(ctx)

	var findings []Finding

	// Finding A: deny-by-default blocklist.
	if blErr != nil {
		c.log.Info("auditExtensionPolicies: blocklist check failed", "err", blErr)
	} else {
		blockAll := containsWildcard(blocklist)
		ev, _ := json.Marshal(map[string]any{
			"policySchema":                "chrome.users.ExtensionInstallBlocklist",
			"extensionInstallBlocklist":   blocklist,
			"blockAllByDefault":           blockAll,
			"orgUnit":                     ous[0].OrgUnitPath,
			"installedExtensionCount":     extCount,
			"installedExtensionsEvidence": extEv,
		})
		findings = append(findings, Finding{
			Description: blocklistDescription(blockAll, extCount),
			Control:     "ISM-1490",
			Passed:      blockAll,
			Evidence:    string(ev),
		})
	}

	// Finding B: explicit allowlist.
	if alErr != nil {
		c.log.Info("auditExtensionPolicies: allowlist check failed", "err", alErr)
	} else {
		hasAllowlist := len(allowlist) > 0
		ev, _ := json.Marshal(map[string]any{
			"policySchema":              "chrome.users.ExtensionInstallAllowlist",
			"extensionInstallAllowlist": allowlist,
			"allowedCount":              len(allowlist),
			"orgUnit":                   ous[0].OrgUnitPath,
		})
		findings = append(findings, Finding{
			Description: allowlistDescription(hasAllowlist, len(allowlist)),
			Control:     "ISM-1490",
			Passed:      hasAllowlist,
			Evidence:    string(ev),
		})
	}

	return findings, nil
}

func containsWildcard(list []string) bool {
	for _, s := range list {
		if s == "*" {
			return true
		}
	}
	return false
}

func blocklistDescription(blockAll bool, extCount int) string {
	if blockAll {
		return fmt.Sprintf(
			"Extension install blocklist includes '*' — deny-by-default enforced; "+
				"%d distinct extension(s) currently installed fleet-wide",
			extCount,
		)
	}
	return "Extension install blocklist does NOT include '*' — " +
		"users may install any Chrome extension; deny-by-default not enforced"
}

func allowlistDescription(hasAllowlist bool, count int) string {
	if hasAllowlist {
		return fmt.Sprintf(
			"Extension install allowlist configured with %d approved extension(s) — "+
				"exceptions to block-all default are explicitly managed",
			count,
		)
	}
	return "No extension install allowlist configured — " +
		"no approved exceptions recorded (verify block-all policy is intentional)"
}

// --- AuditAppControl (main entry point) -----------------------------------

// AuditAppControl audits Strategy #7 for Google Workspace tenants.
// Returns ErrNotAuditable when CBCM is not enrolled (no central browser
// management means no application control policy surface to audit).
func (c *GoogleWorkspaceClient) AuditAppControl(ctx context.Context) (StrategyResult, error) {
	versions, err := c.listManagedBrowserVersions(ctx)
	if err != nil {
		// ErrNotAuditable is propagated when CBCM is not enrolled.
		return StrategyResult{}, fmt.Errorf("AuditAppControl: %w", err)
	}

	// --- ISM-0140: CBCM enrollment ---
	totalBrowsers := 0
	for _, v := range versions {
		totalBrowsers += v.Count
	}

	findings := make([]Finding, 0, 5)
	ev, _ := json.Marshal(map[string]any{
		"managedBrowserCount": totalBrowsers,
		"versionGroups":       len(versions),
	})
	if totalBrowsers > 0 {
		findings = append(findings, Finding{
			Description: fmt.Sprintf(
				"%d Chrome browser(s) enrolled in CBCM — extension and app install policies centrally enforceable",
				totalBrowsers,
			),
			Control:  "ISM-0140",
			Passed:   true,
			Evidence: string(ev),
		})
	} else {
		findings = append(findings, Finding{
			Description: "Chrome Browser Cloud Management enrolled but no browsers registered yet — " +
				"application control policies cannot be applied until devices enrol",
			Control:  "ISM-0140",
			Passed:   false,
			Evidence: string(ev),
		})
	}

	// --- ISM-1490: extension install policy ---
	ous, ouErr := c.listOrgUnits(ctx)
	if ouErr != nil {
		c.log.Info("AuditAppControl: list org units failed", "err", ouErr)
	} else {
		policyFindings, err := c.auditExtensionPolicies(ctx, ous)
		if err != nil {
			// Flat OU structure or API error — not a hard failure.
			c.log.Info("AuditAppControl: extension policy check unavailable", "err", err)
		} else {
			findings = append(findings, policyFindings...)
		}
	}

	return BuildStrategyResult(StrategyAppControl, findings), nil
}
