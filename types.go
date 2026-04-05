// Package witness provides the ASD Essential Eight compliance auditing library
// for Google Workspace and Microsoft 365 tenants.
package witness

import (
	"fmt"
	"time"
)

// MaturityLevel represents ASD Essential Eight Maturity Levels 0–3.
type MaturityLevel int

const (
	ML0 MaturityLevel = iota // Not implemented
	ML1                      // Partially aligned
	ML2                      // Mostly aligned
	ML3                      // Fully aligned
)

func (m MaturityLevel) String() string {
	switch m {
	case ML0:
		return "ML0"
	case ML1:
		return "ML1"
	case ML2:
		return "ML2"
	case ML3:
		return "ML3"
	default:
		return fmt.Sprintf("MaturityLevel(%d)", int(m))
	}
}

// TrafficLight maps a maturity level to a UI colour class.
func (m MaturityLevel) TrafficLight() string {
	switch m {
	case ML3:
		return "green"
	case ML2:
		return "amber"
	case ML1:
		return "red"
	default:
		return "red"
	}
}

// Strategy identifies one of the eight strategies.
type Strategy string

const (
	StrategyAppControl       Strategy = "application_control"
	StrategyPatchApps        Strategy = "patch_applications"
	StrategyMacroSettings    Strategy = "macro_settings"
	StrategyUserAppHardening Strategy = "user_app_hardening"
	StrategyRestrictAdmin    Strategy = "restrict_admin"
	StrategyPatchOS          Strategy = "patch_os"
	StrategyMFA              Strategy = "mfa"
	StrategyBackups          Strategy = "backups"
)

// AllStrategies is the canonical E8 strategy set in ISM order. Do not modify.
var AllStrategies = []Strategy{
	StrategyAppControl,
	StrategyPatchApps,
	StrategyMacroSettings,
	StrategyUserAppHardening,
	StrategyRestrictAdmin,
	StrategyPatchOS,
	StrategyMFA,
	StrategyBackups,
}

// ISMControl maps a strategy to its primary ASD ISM Control ID(s).
var ISMControl = map[Strategy][]string{
	StrategyAppControl:       {"ISM-0140", "ISM-1490"},
	StrategyPatchApps:        {"ISM-1693", "ISM-1704"},
	StrategyMacroSettings:    {"ISM-1671", "ISM-1672"},
	StrategyUserAppHardening: {"ISM-1486", "ISM-1485"},
	StrategyRestrictAdmin:    {"ISM-1507", "ISM-1175"},
	StrategyPatchOS:          {"ISM-1876", "ISM-1877"},
	StrategyMFA:              {"ISM-1504", "ISM-1679"},
	StrategyBackups:          {"ISM-1511", "ISM-1515"},
}

// StrategyResult holds the scored outcome for one strategy.
type StrategyResult struct {
	Strategy  Strategy
	Level     MaturityLevel
	ISMRefs   []string
	Findings  []Finding
	ScannedAt time.Time
}

// Finding is a single compliance observation (pass or fail).
type Finding struct {
	UserHash    string // SHA-256 of email — never store raw PII
	Description string
	Control     string // e.g. "ISM-1504"
	Passed      bool
	Evidence    string // JSON snippet / raw API value
}

// TenantScore is the aggregate E8 result for one tenant.
type TenantScore struct {
	TenantID   string
	TenantName string
	Overall    MaturityLevel // weakest-link across all strategies
	Strategies []StrategyResult
	SyncedAt   time.Time
	PreviousML MaturityLevel // for drift detection
	Drifted    bool
}
