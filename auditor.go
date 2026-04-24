package witness

import "context"

// PlatformAuditor is the common interface for every cloud/SaaS platform that
// the fleet poller can audit. Each platform implements only the E8 strategies
// it can check; strategies it cannot audit return ErrNotAuditable from the
// Run function.
//
// Adding a new platform means implementing this interface and appending the
// client to the FleetPoller's platform list — no changes to the audit loop
// are required.
type PlatformAuditor interface {
	// Name returns the platform label used in logs and metrics.
	// Examples: "microsoft", "google", "aws", "gcpcloud", "jira".
	Name() string

	// Audits returns the set of strategy audit functions this platform
	// supports. Each AuditFunc is called independently; a failure in one
	// does not prevent the others from running.
	Audits() []AuditFunc
}

// AuditFunc pairs a strategy name with the function that audits it.
type AuditFunc struct {
	Strategy Strategy
	Run      func(ctx context.Context) (StrategyResult, error)
}
