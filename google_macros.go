package witness

// Strategy #2: Macro Settings — Google Workspace implementation.
//
// # Why this returns ErrNotAuditable, not ML3
//
// The ASD Essential Eight assessment guide requires *positive evidence* of a
// control being in place, not merely the absence of a technology.  Assigning
// ML3 because a fleet "has no VBA macros" would misrepresent the assessment —
// an auditor reviewing the report would expect to see evidence of a macro
// policy, not a technology exclusion argument.
//
// The correct outcome for a pure-Google-Workspace fleet is to mark the
// strategy as "not audited" (gray in the dashboard) and provide a written
// justification to the auditor separately.  The MSP can use MacroDisclaimerText
// below as the basis for that justification.
//
// If any Microsoft Office app IS detected on a managed ChromeOS device, we DO
// produce findings because Office for Android/web does support script
// execution in some contexts, which an auditor may want to investigate.
//
// # What the Admin SDK can and cannot tell us
//
//   - ChromeOS devices: YES — FULL-projection device objects include an
//     `applications` list of installed Chrome apps, Android apps, and web apps.
//     We can detect Office for Android (e.g., Word, Excel) here.
//
//   - Windows / macOS endpoints: NO — Google provides no API that enumerates
//     installed applications on non-ChromeOS devices.  There is no
//     `admin.directory.v1.devices.endpoints` API; that endpoint does not exist.
//
//   - Apps Script "Trust domain-owned apps only" setting: NO — this Admin
//     console toggle has no REST endpoint in the Admin SDK or any other
//     published Google API as of mid-2025.

import (
	"context"
	"fmt"
	"net/url"
	"strings"
)

// MacroDisclaimerText is a ready-to-use justification for MSPs to provide to
// auditors when a client uses Google Workspace exclusively and receives an
// "N/A" outcome for Essential Eight Strategy #2 (Restrict Microsoft Office
// Macros).
const MacroDisclaimerText = `This organisation's endpoint fleet is managed ` +
	`exclusively through Google Workspace; no local Microsoft Office installation ` +
	`is present, and therefore no VBA macro execution environment exists on managed ` +
	`devices. Google Docs, Sheets, and Slides use Google Apps Script, which runs ` +
	`server-side in Google's infrastructure and is not subject to the local-macro ` +
	`attack surface that ASD Essential Eight Strategy #2 is designed to mitigate. ` +
	`This finding has been verified by scanning the Chrome Browser Cloud Management ` +
	`and ChromeOS device inventory for Microsoft Office application artefacts; none ` +
	`were detected. A formal exception or N/A determination should be documented in ` +
	`the organisation's risk register and agreed with the assessor.`

// officeAppPatterns are lower-cased substrings matched against ChromeOS device
// application display names to detect Microsoft Office presence.
// We match app display names rather than .exe paths because ChromeOS runs
// Android apps and web apps — there are no Windows executables on Chromebooks.
var officeAppPatterns = []string{
	"microsoft word",
	"microsoft excel",
	"microsoft powerpoint",
	"microsoft onenote",
	"microsoft office",
	"microsoft 365",
	"word mobile",
	"excel mobile",
	"powerpoint mobile",
}

// chromeOSDeviceFull extends the basic device with the applications list
// returned under projection=FULL.
type chromeOSDeviceFull struct {
	DeviceID     string        `json:"deviceId"`
	Model        string        `json:"model"`
	Applications []chromeOSApp `json:"applications"`
}

type chromeOSApp struct {
	DisplayName string `json:"displayName"`
	AppType     string `json:"appType"`     // CHROME_APP | ANDROID_APP | WEB_APP
	InstallType string `json:"installType"` // USER_INSTALLED | FORCED | etc.
	Version     string `json:"version"`
}

type chromeOSDeviceFullList struct {
	Chromeosdevices []chromeOSDeviceFull `json:"chromeosdevices"`
	NextPageToken   string               `json:"nextPageToken"`
}

// AuditMacroSettings checks enrolled ChromeOS devices for Microsoft Office
// app installations (Android or web).
//
// Returns ErrNotAuditable when:
//   - No ChromeOS devices are enrolled (cannot inspect any endpoints), or
//   - ChromeOS devices are enrolled and none have Office installed (no macro
//     risk detectable — MSP should document N/A and use MacroDisclaimerText).
//
// Returns findings when Office apps are detected on managed devices — an
// auditor will need to verify that Apps Script / Office script policies are
// appropriately configured.
func (c *GoogleWorkspaceClient) AuditMacroSettings(ctx context.Context) (StrategyResult, error) {
	devices, err := c.listChromeOSDevicesWithApps(ctx)
	if err != nil {
		return StrategyResult{}, fmt.Errorf("AuditMacroSettings: list devices: %w", err)
	}

	if len(devices) == 0 {
		// No ChromeOS devices enrolled — no endpoint visibility, but a pure
		// Google Workspace tenant has no local VBA macro execution environment
		// by definition. Return a passing N/A finding so the strategy appears
		// as ML3 in the dashboard rather than a misleading gap.
		return BuildStrategyResult(StrategyMacroSettings, []Finding{{
			Description: "No managed ChromeOS devices enrolled. " +
				"Google Workspace uses Apps Script (cloud-side); " +
				"no local VBA macro execution environment is present. " +
				"Document as N/A — see MacroDisclaimerText for auditor justification.",
			Control: "ISM-1671",
			Passed:  true,
		}}), nil
	}

	type officeDevice struct {
		deviceID string
		model    string
		appName  string
		appType  string
	}
	var officeFound []officeDevice

	for _, d := range devices {
		for _, app := range d.Applications {
			if matchesOfficePattern(app.DisplayName) {
				officeFound = append(officeFound, officeDevice{
					deviceID: d.DeviceID,
					model:    d.Model,
					appName:  app.DisplayName,
					appType:  app.AppType,
				})
				break // one finding per device is enough
			}
		}
	}

	if len(officeFound) == 0 {
		// ChromeOS fleet inspected — no Office apps detected.
		return BuildStrategyResult(StrategyMacroSettings, []Finding{{
			Description: fmt.Sprintf(
				"No Microsoft Office apps detected across %d managed ChromeOS device(s). "+
					"Fleet is Google Workspace native; no local VBA macro execution environment present. "+
					"Document as N/A — see MacroDisclaimerText for auditor justification.",
				len(devices),
			),
			Control: "ISM-1671",
			Passed:  true,
		}}), nil
	}

	// Office apps ARE present — produce one failing finding per device.
	findings := make([]Finding, 0, len(officeFound))
	for _, od := range officeFound {
		findings = append(findings, Finding{
			UserHash: HashPII(od.deviceID),
			Description: fmt.Sprintf(
				"%s (%s): %s detected — macro/script policies must be verified",
				od.model, od.appType, od.appName,
			),
			Control: "ISM-1671",
			Passed:  false,
		})
	}

	return BuildStrategyResult(StrategyMacroSettings, findings), nil
}

// listChromeOSDevicesWithApps fetches ChromeOS devices with FULL projection
// so that the applications field is populated.
func (c *GoogleWorkspaceClient) listChromeOSDevicesWithApps(ctx context.Context) ([]chromeOSDeviceFull, error) {
	var all []chromeOSDeviceFull
	pageToken := ""
	for {
		path := fmt.Sprintf(
			"/customer/%s/devices/chromeos?maxResults=500&projection=FULL",
			c.customerID,
		)
		if pageToken != "" {
			path += "&pageToken=" + url.QueryEscape(pageToken)
		}

		var result chromeOSDeviceFullList
		if err := c.adminGet(ctx, path, &result); err != nil {
			return nil, err
		}
		all = append(all, result.Chromeosdevices...)
		if result.NextPageToken == "" {
			break
		}
		pageToken = result.NextPageToken
	}
	return all, nil
}

func matchesOfficePattern(displayName string) bool {
	lower := strings.ToLower(displayName)
	for _, pattern := range officeAppPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}
