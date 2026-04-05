package witness

import (
	"log/slog"
	"time"
)

// Scorer aggregates per-strategy results into a tenant-level TenantScore
// using the "Weakest Link" principle mandated by ASD ACSC.
type Scorer struct {
	log *slog.Logger
}

// NewScorer creates a Scorer.
func NewScorer(log *slog.Logger) *Scorer {
	return &Scorer{log: log}
}

// Score applies the weakest-link rule across all strategy results and
// returns a fully populated TenantScore.
//
// Each strategy is scored independently: one failing finding degrades it by
// one level. The overall MaturityLevel is then MIN(all strategy levels).
// The input slice is not modified.
func (s *Scorer) Score(tenantID, tenantName string, results []StrategyResult, previous MaturityLevel) TenantScore {
	overall := ML3

	scored := make([]StrategyResult, len(results))
	copy(scored, results)

	for i, r := range scored {
		effective := computeEffectiveLevel(r)
		scored[i].Level = effective
		if effective < overall {
			overall = effective
		}
	}

	score := TenantScore{
		TenantID:   tenantID,
		TenantName: tenantName,
		Overall:    overall,
		Strategies: scored,
		SyncedAt:   time.Now().UTC(),
		PreviousML: previous,
		Drifted:    previous != 0 && previous != overall,
	}

	s.log.Info("tenant scored",
		"tenant", tenantID,
		"overall", overall.String(),
		"drifted", score.Drifted,
		"strategies", len(results),
	)
	return score
}

// computeEffectiveLevel applies the weakest-link within a single strategy.
// Each failing finding degrades the level by one (minimum ML0), so:
//   - 0 failures → ML3
//   - 1 failure  → ML2
//   - 2 failures → ML1
//   - 3+ failures → ML0
func computeEffectiveLevel(r StrategyResult) MaturityLevel {
	level := ML3
	for _, f := range r.Findings {
		if f.Passed {
			continue
		}
		if level > ML0 {
			level--
		}
	}
	return level
}
