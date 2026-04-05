package witness

import (
	"errors"
	"fmt"
)

// ErrNotAuditable is returned by audit methods when the required API, service,
// or device class is not enrolled/enabled for this tenant. The strategy will
// remain "not audited" (gray) in the dashboard rather than failing.
var ErrNotAuditable = errors.New("witness: not auditable for this tenant")

// ConsentRevokedError is returned when the Graph API responds with HTTP 401 or
// 403 in a way that indicates admin consent was not granted or was removed.
//
// Unlike transient network errors, this condition persists until the customer's
// Global Administrator re-approves the MSP application via the consent URL.
type ConsentRevokedError struct {
	TenantID   string
	StatusCode int
}

func (e *ConsentRevokedError) Error() string {
	return fmt.Sprintf(
		"graph: application permission denied for tenant %s (HTTP %d) — "+
			"admin consent required or revoked; direct the customer to the Connect Microsoft 365 flow",
		e.TenantID, e.StatusCode,
	)
}

// ClaimsChallengeError is returned when Microsoft Graph issues a
// Continuous Access Evaluation / Claims Challenge requiring interactive re-auth.
type ClaimsChallengeError struct {
	Path      string
	Challenge string
}

func (e *ClaimsChallengeError) Error() string {
	return fmt.Sprintf("graph: claims challenge on %s — re-authentication required: %s", e.Path, e.Challenge)
}
