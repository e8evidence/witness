package witness

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"
)

// HashPII returns the hex-encoded SHA-256 of a PII string (email, name).
// This must be called before persisting any user-identifying data.
func HashPII(value string) string {
	sum := sha256.Sum256([]byte(value))
	return fmt.Sprintf("%x", sum)
}

// MarshalFindings serialises a []Finding slice to compact JSON for storage.
func MarshalFindings(findings []Finding) (string, error) {
	b, err := json.Marshal(findings)
	if err != nil {
		return "", fmt.Errorf("marshal findings: %w", err)
	}
	return string(b), nil
}

// PersistFunc writes a TenantScore to the tenant's database.
// It is intentionally a function type rather than an interface to keep the
// audit package focused on business logic and free of storage dependencies.
type PersistFunc func(ctx context.Context, score TenantScore) error

// BuildStrategyResult constructs a StrategyResult for a completed audit.
// Level is initialised to ML3; Scorer.Score will lower it via the weakest-link
// rule when findings are evaluated.
func BuildStrategyResult(strategy Strategy, findings []Finding) StrategyResult {
	return StrategyResult{
		Strategy:  strategy,
		Level:     ML3,
		ISMRefs:   ISMControl[strategy],
		Findings:  findings,
		ScannedAt: time.Now().UTC(),
	}
}
