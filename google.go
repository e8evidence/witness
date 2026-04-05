package witness

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// AuditPrivileges lists Super Admin accounts and verifies 2-Step Verification
// (2SV) is enforced — required for ML2 per ISM-1507 and ISM-1175.
func (c *GoogleWorkspaceClient) AuditPrivileges(ctx context.Context) (StrategyResult, error) {
	admins, err := c.listSuperAdmins(ctx)
	if err != nil {
		return StrategyResult{}, fmt.Errorf("AuditPrivileges: list super admins: %w", err)
	}

	findings := make([]Finding, 0, len(admins))
	for _, a := range admins {
		evidence, _ := json.Marshal(map[string]any{
			"isEnrolledIn2Sv": a.IsEnrolledIn2Sv,
			"isAdmin":         a.IsAdmin,
		})
		findings = append(findings, Finding{
			UserHash:    HashPII(a.PrimaryEmail),
			Description: privilegeDescription(a.PrimaryEmail, a.IsEnrolledIn2Sv),
			Control:     "ISM-1507",
			Passed:      a.IsEnrolledIn2Sv,
			Evidence:    string(evidence),
		})
	}

	return BuildStrategyResult(StrategyRestrictAdmin, findings), nil
}

// AuditChrome checks that Chrome browsers enrolled in CBCM are patched to the
// current major version, satisfying ISM-1693 (patches within one month for ML2).
//
// Chrome releases a new major version approximately every 4 weeks, so any
// browser running a major version older than the newest in the fleet has
// effectively missed at least one monthly patch cycle. The compliance check
// uses the Chrome Management Reports API countBrowserVersions endpoint (the
// same API and scopes used by countInstalledApps — no additional enablement
// required). There is no Admin SDK Directory API endpoint for Chrome browsers.
//
// Returns ErrNotAuditable when no managed browsers are found.
func (c *GoogleWorkspaceClient) AuditChrome(ctx context.Context) (StrategyResult, error) {
	versions, err := c.listManagedBrowserVersions(ctx)
	if err != nil {
		return StrategyResult{}, fmt.Errorf("AuditChrome: %w", err)
	}
	if len(versions) == 0 {
		return StrategyResult{}, fmt.Errorf(
			"AuditChrome: no managed Chrome browsers found: %w", ErrNotAuditable)
	}

	// Find the newest major version present in the fleet — that is the
	// expected patch level. Browsers on an older major version have not
	// applied the latest monthly patch cycle (ISM-1693).
	maxMajor := 0
	for _, v := range versions {
		if m := parseMajorVersion(v.Version); m > maxMajor {
			maxMajor = m
		}
	}

	findings := make([]Finding, 0, len(versions))
	for _, v := range versions {
		major := parseMajorVersion(v.Version)
		upToDate := major >= maxMajor
		ev, _ := json.Marshal(map[string]any{
			"version":      v.Version,
			"majorVersion": major,
			"newestMajor":  maxMajor,
			"channel":      v.Channel,
			"system":       v.System,
			"count":        v.Count,
		})
		findings = append(findings, Finding{
			Description: chromePatchDesc(v.Version, v.Channel, v.System, v.Count, upToDate, maxMajor),
			Control:     "ISM-1693",
			Passed:      upToDate,
			Evidence:    string(ev),
		})
	}

	return BuildStrategyResult(StrategyPatchApps, findings), nil
}

// AuditMFA checks whether 2-Step Verification is enrolled for all users in the
// domain, satisfying ISM-1504 and ISM-1679 (MFA for all users, not just admins).
func (c *GoogleWorkspaceClient) AuditMFA(ctx context.Context) (StrategyResult, error) {
	users, err := c.listAllUsers(ctx)
	if err != nil {
		return StrategyResult{}, fmt.Errorf("AuditMFA: list users: %w", err)
	}

	findings := make([]Finding, 0, len(users))
	for _, u := range users {
		evidence, _ := json.Marshal(map[string]any{
			"isEnrolledIn2Sv": u.IsEnrolledIn2Sv,
			"isAdmin":         u.IsAdmin,
		})
		findings = append(findings, Finding{
			UserHash:    HashPII(u.PrimaryEmail),
			Description: mfaDescription(u.PrimaryEmail, u.IsEnrolledIn2Sv),
			Control:     "ISM-1504",
			Passed:      u.IsEnrolledIn2Sv,
			Evidence:    string(evidence),
		})
	}

	return BuildStrategyResult(StrategyMFA, findings), nil
}

// --- Description helpers --------------------------------------------------

func chromePatchDesc(version, channel, system string, count int, upToDate bool, newestMajor int) string {
	if upToDate {
		return fmt.Sprintf(
			"%d %s Chrome browser(s) on v%s (%s) — current (major version matches fleet maximum v%d)",
			count, system, version, channel, newestMajor,
		)
	}
	return fmt.Sprintf(
		"%d %s Chrome browser(s) on v%s (%s) — OUTDATED (fleet is at v%d; update within monthly patch window per ISM-1693)",
		count, system, version, channel, newestMajor,
	)
}

// parseMajorVersion extracts the major version integer from a Chrome version
// string such as "124.0.6367.82". Returns 0 if the string is unparseable.
func parseMajorVersion(version string) int {
	if i := strings.IndexByte(version, '.'); i > 0 {
		n, _ := strconv.Atoi(version[:i])
		return n
	}
	return 0
}

func privilegeDescription(email string, enrolled bool) string {
	h := HashPII(email)
	if enrolled {
		return fmt.Sprintf("Super Admin %s…%s has 2SV enrolled", h[:8], h[len(h)-4:])
	}
	return fmt.Sprintf("Super Admin %s…%s lacks 2SV — REQUIRED for ML2 (ISM-1507)", h[:8], h[len(h)-4:])
}

func mfaDescription(email string, enrolled bool) string {
	if enrolled {
		return fmt.Sprintf("%s: 2SV enrolled", HashPII(email))
	}
	return fmt.Sprintf("%s: 2SV NOT enrolled", HashPII(email))
}
