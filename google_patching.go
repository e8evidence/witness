package witness

// Strategy #6: Patch Operating Systems — Google Workspace implementation.
//
// # What this audits
//
// Two device classes, each contributing findings:
//
//  1. ChromeOS managed devices (Admin SDK chromeosdevices list):
//     - ISM-1877: device Auto-Update Expiry (AUE) date not exceeded — EOL
//       ChromeOS devices cannot receive OS updates regardless of settings.
//     - ISM-1876: last sync within 30 days (ML1 threshold).
//     - ISM-1876: last sync within 14 days (ML2/ML3 threshold).
//     These three per-device findings allow the weakest-link scorer to produce
//     ML0 (EOL device), ML1 (stale > 30 d), ML2 (stale 14–30 d), or ML3
//     (all devices synced within 14 days).
//
//  2. Endpoint Verification devices (Chrome Management Telemetry API):
//     Windows, macOS, and Linux endpoints enrolled in BeyondCorp/Endpoint
//     Verification expose OS version and last sync time via the Chrome
//     Management Telemetry API.  A 14-day staleness check is applied with
//     ISM-1876.  This path is silently skipped when no telemetry data is
//     available (e.g. Endpoint Verification not deployed).
//
// # What this does NOT audit (and why)
//
//   - "Latest Stable" ChromeOS version comparison: Google provides no Admin
//     SDK or public API that returns the current latest ChromeOS version.
//     Hardcoding a version string would become stale between releases.
//     The AUE date + sync recency are the correct proxies for "is this device
//     receiving OS updates".
//
//   - `admin.directory.v1.devices.endpoints`: this API does not exist.
//     Windows/Mac OS data is available only via Chrome Management Telemetry
//     (BeyondCorp Endpoint Verification) or a third-party MDM.
//
//   - `isWithinPatchWindow(severity string)`: device reboot history and
//     per-patch critical/high classification are not exposed by any Google
//     Workspace API.
//
//   - Concurrent page fetching with sync.WaitGroup: pagination in the Admin
//     SDK is sequential by design (each page requires the previous token).
//     Parallelism can only be applied across independent device-class queries,
//     which adds complexity without meaningful latency benefit given typical
//     fleet sizes.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

const (
	// patchWindowML2 is ISM-1876: OS patches applied within 2 weeks.
	patchWindowML2 = 14 * 24 * time.Hour
	// patchWindowML1 is ISM-1876 lower bound: devices unsynced beyond this
	// are considered stale with unknown patch status.
	patchWindowML1 = 30 * 24 * time.Hour
)

// AuditPatchOS audits OS patch currency for managed ChromeOS devices and, when
// available, Endpoint Verification-enrolled Windows/macOS/Linux endpoints.
// Returns ErrNotAuditable when no devices of either class are enrolled.
func (c *GoogleWorkspaceClient) AuditPatchOS(ctx context.Context) (StrategyResult, error) {
	var findings []Finding

	// --- ChromeOS devices -------------------------------------------------
	chromeosFindings, err := c.auditChromeOSPatch(ctx)
	if err != nil && !errors.Is(err, ErrNotAuditable) {
		return StrategyResult{}, fmt.Errorf("AuditPatchOS: ChromeOS: %w", err)
	}
	findings = append(findings, chromeosFindings...)

	// --- Endpoint Verification (Windows/Mac/Linux) — best effort ----------
	evFindings, err := c.auditEndpointVerificationPatch(ctx)
	if err != nil {
		// EV not deployed or API unavailable — not a hard failure.
		c.log.Info("AuditPatchOS: Endpoint Verification unavailable", "err", err)
	} else {
		findings = append(findings, evFindings...)
	}

	if len(findings) == 0 {
		return StrategyResult{}, fmt.Errorf(
			"AuditPatchOS: no managed devices found (ChromeOS or Endpoint Verification): %w",
			ErrNotAuditable,
		)
	}

	return BuildStrategyResult(StrategyPatchOS, findings), nil
}

// --- ChromeOS audit -------------------------------------------------------

func (c *GoogleWorkspaceClient) auditChromeOSPatch(ctx context.Context) ([]Finding, error) {
	devices, err := c.listChromeOSDevices(ctx)
	if err != nil {
		return nil, fmt.Errorf("auditChromeOSPatch: %w", err)
	}
	if len(devices) == 0 {
		return nil, fmt.Errorf("auditChromeOSPatch: no ChromeOS devices enrolled: %w", ErrNotAuditable)
	}

	now := time.Now().UTC()
	findings := make([]Finding, 0, len(devices)*3)

	for _, d := range devices {
		ev, _ := json.Marshal(map[string]string{
			"deviceId":       d.DeviceID,
			"model":          d.Model,
			"osVersion":      d.OsVersion,
			"lastSync":       d.LastSync,
			"supportEndDate": d.SupportEndDate,
		})
		evStr := string(ev)

		// Finding A — ISM-1877: device must not be past its Auto-Update Expiry.
		// An EOL ChromeOS device will never receive OS updates, making it
		// structurally non-compliant regardless of sync recency.
		supported, aueMsg := checkChromeOSSupport(d.SupportEndDate, now)
		findings = append(findings, Finding{
			UserHash:    HashPII(d.DeviceID),
			Description: fmt.Sprintf("ChromeOS %s (%s): %s", d.Model, d.OsVersion, aueMsg),
			Control:     "ISM-1877",
			Passed:      supported,
			Evidence:    evStr,
		})

		lastSync, _ := time.Parse(time.RFC3339Nano, d.LastSync)
		age := now.Sub(lastSync)

		// Finding B — ISM-1876 ML1 threshold: synced within 30 days.
		findings = append(findings, Finding{
			UserHash:    HashPII(d.DeviceID),
			Description: patchStatusDesc(d.Model, d.OsVersion, age, patchWindowML1, "30-day"),
			Control:     "ISM-1876",
			Passed:      age <= patchWindowML1,
			Evidence:    evStr,
		})

		// Finding C — ISM-1876 ML2 threshold: synced within 14 days.
		findings = append(findings, Finding{
			UserHash:    HashPII(d.DeviceID),
			Description: patchStatusDesc(d.Model, d.OsVersion, age, patchWindowML2, "14-day"),
			Control:     "ISM-1876",
			Passed:      age <= patchWindowML2,
			Evidence:    evStr,
		})
	}

	return findings, nil
}

// checkChromeOSSupport returns (supported, description) for a device's AUE date.
// An empty or unparseable supportEndDate is treated as supported (unknown).
func checkChromeOSSupport(supportEndDate string, now time.Time) (bool, string) {
	if supportEndDate == "" {
		return true, "auto-update expiry date unknown — verify device AUE"
	}
	// Admin SDK returns "YYYY-MM-DD" without a time component.
	t, err := time.Parse("2006-01-02", supportEndDate)
	if err != nil {
		return true, fmt.Sprintf("auto-update expiry date unparseable (%s)", supportEndDate)
	}
	if now.After(t) {
		return false, fmt.Sprintf(
			"AUTO-UPDATE EXPIRED on %s — device will not receive OS updates (ISM-1877 fail)",
			supportEndDate,
		)
	}
	return true, fmt.Sprintf("auto-update supported until %s", supportEndDate)
}

func patchStatusDesc(model, osVersion string, age, window time.Duration, label string) string {
	days := int(age / (24 * time.Hour))
	if age <= window {
		return fmt.Sprintf("ChromeOS %s (%s) — last sync %dd ago (within %s patch window)", model, osVersion, days, label)
	}
	return fmt.Sprintf("ChromeOS %s (%s) — last sync %dd ago (EXCEEDS %s patch window)", model, osVersion, days, label)
}

// --- Endpoint Verification ------------------------------------------------
//
// Endpoint Verification-enrolled devices (Windows, macOS, Linux) appear in
// the Chrome Management Telemetry API under osPlatformType values of
// WINDOWS, MAC, or LINUX.  This is separate from ChromeOS devices.
//
// NOTE: `admin.directory.v1.devices.endpoints` does not exist.
// Endpoint Verification data is only available via:
//   - Chrome Management Telemetry API (requires BeyondCorp EV deployment)
//   - Third-party MDM integrations (Intune, Jamf) — outside scope

type evDevice struct {
	DeviceID string `json:"deviceId"`
	Customer string `json:"customer"`
	OsInfo   struct {
		OsVersion      string `json:"osVersion"`
		OsPlatformType string `json:"osPlatformType"` // WINDOWS | MAC | LINUX | CHROME_OS
	} `json:"osInfo"`
	DeviceInfo struct {
		LastRegistrationTime string `json:"lastRegistrationTime"`
	} `json:"deviceInfo"`
}

type evDeviceList struct {
	Devices       []evDevice `json:"devices"`
	NextPageToken string     `json:"nextPageToken"`
}

// auditEndpointVerificationPatch fetches non-ChromeOS devices from the Chrome
// Management Telemetry API and checks sync recency for each.
func (c *GoogleWorkspaceClient) auditEndpointVerificationPatch(ctx context.Context) ([]Finding, error) {
	devices, err := c.listEVDevices(ctx)
	if err != nil {
		return nil, err
	}
	if len(devices) == 0 {
		return nil, nil // EV not deployed — not an error
	}

	now := time.Now().UTC()
	findings := make([]Finding, 0, len(devices))

	for _, d := range devices {
		// Skip ChromeOS — already covered by auditChromeOSPatch.
		if d.OsInfo.OsPlatformType == "CHROME_OS" {
			continue
		}

		lastReg, _ := time.Parse(time.RFC3339, d.DeviceInfo.LastRegistrationTime)
		age := now.Sub(lastReg)
		withinWindow := age <= patchWindowML2

		ev, _ := json.Marshal(map[string]string{
			"deviceId":             d.DeviceID,
			"osPlatform":           d.OsInfo.OsPlatformType,
			"osVersion":            d.OsInfo.OsVersion,
			"lastRegistrationTime": d.DeviceInfo.LastRegistrationTime,
		})

		findings = append(findings, Finding{
			UserHash: HashPII(d.DeviceID),
			Description: fmt.Sprintf(
				"%s endpoint OS %s — last EV check-in %dd ago (%s)",
				d.OsInfo.OsPlatformType, d.OsInfo.OsVersion, int(age/(24*time.Hour)),
				evSyncStatus(withinWindow),
			),
			Control:  "ISM-1876",
			Passed:   withinWindow,
			Evidence: string(ev),
		})
	}

	return findings, nil
}

func evSyncStatus(withinWindow bool) string {
	if withinWindow {
		return "within 14-day patch window"
	}
	return "STALE — patch status unknown"
}

// listEVDevices fetches non-ChromeOS endpoint devices from the Chrome
// Management Telemetry API with pagination.
func (c *GoogleWorkspaceClient) listEVDevices(ctx context.Context) ([]evDevice, error) {
	var all []evDevice
	pageToken := ""
	for {
		path := fmt.Sprintf("%s/customers/%s/telemetry/devices?pageSize=200", chromeMgmtBase, c.customerID)
		if pageToken != "" {
			path += "&pageToken=" + url.QueryEscape(pageToken)
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, path, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+c.token)

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("EV telemetry GET: %w", err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusForbidden {
			// EV not enabled or scope not authorised — not a hard error.
			return nil, fmt.Errorf("EV telemetry unavailable: HTTP %d", resp.StatusCode)
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("EV telemetry GET: HTTP %d: %s", resp.StatusCode, body)
		}

		var result evDeviceList
		if err := json.Unmarshal(body, &result); err != nil {
			return nil, fmt.Errorf("EV telemetry decode: %w", err)
		}
		all = append(all, result.Devices...)
		if result.NextPageToken == "" {
			break
		}
		pageToken = result.NextPageToken
	}
	return all, nil
}
