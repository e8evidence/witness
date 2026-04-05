package witness

// Strategy #8: Backups — Google Workspace implementation.
//
// Detects third-party cloud-to-cloud backup solutions via OAuth token scanning
// and checks Google Vault licensing.
//
// Three findings map to E8 maturity levels via the weakest-link rule:
//
//	ISM-1511 (vendor detected) + ISM-1515 (immutable storage) + ISM-1511 (Vault)
//	  all pass  → ML3  (independent backup + immutable + Vault retention)
//	  1 failure → ML2  (e.g. vendor found but no immutable storage evidence)
//	  2 failures→ ML1  (e.g. Vault only, no independent backup)
//	  3 failures→ ML0  (no backup or retention capability detected)
//
// Detection method: OAuth token scan across super admins and a sample of
// regular users. Service-account (DWD) backup solutions are NOT detectable
// this way — only OAuth-authorised apps appear in the token list.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// backupVendorEntry describes a known cloud-to-cloud backup provider.
type backupVendorEntry struct {
	pattern           string // matched case-insensitively against OAuth token displayText
	name              string
	supportsImmutable bool // true when vendor supports S3 Object Lock or equivalent (ISM-1515)
}

// knownBackupVendors is the lookup table of recognised cloud-to-cloud backup
// solutions. Patterns are matched against OAuth app display names.
var knownBackupVendors = []backupVendorEntry{
	{pattern: "afi", name: "Afi.ai", supportsImmutable: true},
	{pattern: "backupify", name: "Backupify (Datto)", supportsImmutable: true},
	{pattern: "datto", name: "Datto SaaS Protection", supportsImmutable: true},
	{pattern: "acronis", name: "Acronis Cyber Backup", supportsImmutable: true},
	{pattern: "veeam", name: "Veeam Backup", supportsImmutable: true},
	{pattern: "keepit", name: "Keepit", supportsImmutable: true},
	{pattern: "dropsuite", name: "Dropsuite", supportsImmutable: false},
	{pattern: "spanning", name: "Spanning Backup", supportsImmutable: false},
	{pattern: "syscloud", name: "SysCloud", supportsImmutable: false},
	{pattern: "synology", name: "Synology Active Backup", supportsImmutable: false},
	{pattern: "spinbackup", name: "SpinBackup", supportsImmutable: false},
	{pattern: "cloudally", name: "CloudAlly", supportsImmutable: false},
}

// backupRelevantScopes are the OAuth scopes that provide the data-read access
// required by a backup solution.
var backupRelevantScopes = map[string]bool{
	"https://www.googleapis.com/auth/drive":          true,
	"https://www.googleapis.com/auth/drive.readonly": true,
	"https://mail.google.com/":                       true,
	"https://www.googleapis.com/auth/gmail.readonly": true,
}

type oauthToken struct {
	DisplayText string   `json:"displayText"`
	ClientID    string   `json:"clientId"`
	Scopes      []string `json:"scopes"`
}

type oauthTokenList struct {
	Items []oauthToken `json:"items"`
}

// AuditBackups scans for evidence of a third-party cloud-to-cloud backup
// solution and Google Vault licensing.
func (c *GoogleWorkspaceClient) AuditBackups(ctx context.Context) (StrategyResult, error) {
	// --- Check 1 & 2: scan OAuth tokens for known backup vendors ----------
	vendor, err := c.detectBackupVendor(ctx)
	if err != nil {
		// Token scan failure is non-fatal: fall through with no vendor.
		c.log.Warn("AuditBackups: token scan failed", "err", err)
	}

	vendorFound := vendor != nil
	vendorImmutable := vendor != nil && vendor.supportsImmutable

	vn := ""
	if vendor != nil {
		vn = vendor.name
	}
	vendorEvidence, _ := json.Marshal(map[string]any{
		"vendorDetected":    vendorFound,
		"vendorName":        vn,
		"supportsImmutable": vendorImmutable,
		"detectionMethod":   "oauth_token_scan",
	})

	// --- Check 3: Google Vault licensing ----------------------------------
	_, vaultLicensed, vaultErr := c.listVaultMatters(ctx)
	vaultLicensed = vaultErr == nil && vaultLicensed

	vaultEvidence, _ := json.Marshal(map[string]any{
		"vaultLicensed": vaultLicensed,
	})

	findings := []Finding{
		{
			Description: backupVendorDescription(vendor),
			Control:     "ISM-1511",
			Passed:      vendorFound,
			Evidence:    string(vendorEvidence),
		},
		{
			Description: immutableDescription(vendor),
			Control:     "ISM-1515",
			Passed:      vendorImmutable,
			Evidence:    string(vendorEvidence),
		},
		{
			Description: vaultDescription(vaultLicensed),
			Control:     "ISM-1511",
			Passed:      vaultLicensed,
			Evidence:    string(vaultEvidence),
		},
	}

	return BuildStrategyResult(StrategyBackups, findings), nil
}

// detectBackupVendor scans OAuth tokens for admin users and a sample of
// regular users, returning the first matching backup vendor entry.
// Returns nil (no error) when no vendor is detected.
func (c *GoogleWorkspaceClient) detectBackupVendor(ctx context.Context) (*backupVendorEntry, error) {
	admins, err := c.listSuperAdmins(ctx)
	if err != nil {
		return nil, fmt.Errorf("detectBackupVendor: list admins: %w", err)
	}

	// Sample regular users — cap at 20 to avoid rate-limit pileup.
	regularPath := fmt.Sprintf("/users?customer=%s&maxResults=20&projection=basic", c.customerID)
	var regularList gsuiteUserList
	_ = c.adminGet(ctx, regularPath, &regularList) // best-effort

	for _, u := range collectUsersToScan(admins, regularList.Users) {
		tokens, err := c.listUserTokens(ctx, u.PrimaryEmail)
		if err != nil {
			c.log.Warn("detectBackupVendor: list tokens", "user", HashPII(u.PrimaryEmail), "err", err)
			continue
		}
		if v := matchBackupVendor(tokens); v != nil {
			return v, nil
		}
	}
	return nil, nil
}

// listUserTokens returns the OAuth tokens granted by a single user.
func (c *GoogleWorkspaceClient) listUserTokens(ctx context.Context, userEmail string) ([]oauthToken, error) {
	path := fmt.Sprintf("/users/%s/tokens", url.PathEscape(userEmail))
	var result oauthTokenList
	if err := c.adminGet(ctx, path, &result); err != nil {
		return nil, err
	}
	return result.Items, nil
}

// matchBackupVendor returns the first vendor whose name pattern appears in
// any token's displayText AND whose token grants a backup-relevant scope.
func matchBackupVendor(tokens []oauthToken) *backupVendorEntry {
	for _, tok := range tokens {
		if !hasBackupScope(tok.Scopes) {
			continue
		}
		display := strings.ToLower(tok.DisplayText)
		for j := range knownBackupVendors {
			if strings.Contains(display, knownBackupVendors[j].pattern) {
				return &knownBackupVendors[j]
			}
		}
	}
	return nil
}

func hasBackupScope(scopes []string) bool {
	for _, s := range scopes {
		if backupRelevantScopes[s] {
			return true
		}
	}
	return false
}

func backupVendorDescription(v *backupVendorEntry) string {
	if v == nil {
		return "No independent cloud-to-cloud backup detected — Google Vault is not a substitute for Strategy #8"
	}
	return fmt.Sprintf("Backup solution detected: %s (OAuth token with data-read scope)", v.name)
}

func immutableDescription(v *backupVendorEntry) string {
	if v == nil {
		return "No backup vendor detected — immutable/offline storage cannot be confirmed"
	}
	if v.supportsImmutable {
		return fmt.Sprintf("%s supports immutable backup storage (S3 Object Lock or equivalent)", v.name)
	}
	return fmt.Sprintf("%s detected but immutable/offline storage not confirmed for this vendor", v.name)
}

func vaultDescription(licensed bool) string {
	if licensed {
		return "Google Vault licensed — provides data retention and e-discovery as a secondary safety net"
	}
	return "Google Vault not licensed — no data retention or e-discovery capability"
}
