package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/e8evidence/witness"
)

func TestEnvOr_ExplicitValueWins(t *testing.T) {
	t.Setenv("SOME_KEY", "env-val")
	got := envOr("explicit", "SOME_KEY")
	if got != "explicit" {
		t.Errorf("expected 'explicit', got %q", got)
	}
}

func TestEnvOr_FallsBackToEnv(t *testing.T) {
	t.Setenv("SOME_KEY", "from-env")
	got := envOr("", "SOME_KEY")
	if got != "from-env" {
		t.Errorf("expected 'from-env', got %q", got)
	}
}

func TestEnvOr_BothEmpty(t *testing.T) {
	got := envOr("", "MISSING_KEY_THAT_DOES_NOT_EXIST_XYZ123")
	if got != "" {
		t.Errorf("expected empty string, got %q", got)
	}
}

func TestCountFindings(t *testing.T) {
	tests := []struct {
		name     string
		findings []witness.Finding
		pass     int
		fail     int
	}{
		{
			name:     "all pass",
			findings: []witness.Finding{{Passed: true}, {Passed: true}},
			pass:     2,
			fail:     0,
		},
		{
			name:     "all fail",
			findings: []witness.Finding{{Passed: false}, {Passed: false}},
			pass:     0,
			fail:     2,
		},
		{
			name:     "mixed",
			findings: []witness.Finding{{Passed: true}, {Passed: false}, {Passed: true}},
			pass:     2,
			fail:     1,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pass, fail := countFindings(tc.findings)
			if pass != tc.pass || fail != tc.fail {
				t.Errorf("countFindings() = (%d, %d), want (%d, %d)", pass, fail, tc.pass, tc.fail)
			}
		})
	}
}

func TestPrintScore_ContainsStrategyAndLevel(t *testing.T) {
	score := witness.TenantScore{
		TenantID: "test-tenant",
		Overall:  witness.ML2,
		SyncedAt: time.Now(),
		Strategies: []witness.StrategyResult{
			{
				Strategy: witness.StrategyMFA,
				Level:    witness.ML3,
				Findings: []witness.Finding{{Passed: true}},
			},
		},
	}

	var buf bytes.Buffer
	err := printScore(&buf, "Google Workspace", "test-tenant", score, nil, false)
	if err != nil {
		t.Fatalf("printScore returned error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, string(witness.StrategyMFA)) {
		t.Errorf("output missing strategy name %q: %s", witness.StrategyMFA, out)
	}
	if !strings.Contains(out, witness.ML3.String()) {
		t.Errorf("output missing level %q: %s", witness.ML3.String(), out)
	}
	if !strings.Contains(out, "Overall") {
		t.Errorf("output missing 'Overall': %s", out)
	}
	if !strings.Contains(out, "test-tenant") {
		t.Errorf("output missing tenant ID: %s", out)
	}
}

func TestPrintScore_NA_Shown(t *testing.T) {
	score := witness.TenantScore{
		TenantID: "test-tenant",
		Overall:  witness.ML3,
		SyncedAt: time.Now(),
	}
	nas := []witness.Strategy{witness.StrategyMacroSettings}

	var buf bytes.Buffer
	err := printScore(&buf, "Google Workspace", "test-tenant", score, nas, false)
	if err != nil {
		t.Fatalf("printScore returned error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "N/A") {
		t.Errorf("expected 'N/A' in output for not-auditable strategy, got: %s", out)
	}
}

func TestPrintScore_Verbose_ShowsFindings(t *testing.T) {
	score := witness.TenantScore{
		TenantID: "test-tenant",
		Overall:  witness.ML2,
		SyncedAt: time.Now(),
		Strategies: []witness.StrategyResult{
			{
				Strategy: witness.StrategyMFA,
				Level:    witness.ML2,
				Findings: []witness.Finding{
					{Passed: true, Description: "User A passes", Control: "ISM-1504"},
					{Passed: false, Description: "User B fails", Control: "ISM-1504"},
				},
			},
		},
	}

	var buf bytes.Buffer
	err := printScore(&buf, "Google Workspace", "test-tenant", score, nil, true)
	if err != nil {
		t.Fatalf("printScore returned error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "✓") {
		t.Errorf("expected '✓' in verbose output, got: %s", out)
	}
	if !strings.Contains(out, "✗") {
		t.Errorf("expected '✗' in verbose output, got: %s", out)
	}
}

// stub audit function that returns a canned result
func makeStubAudit(s witness.Strategy, result witness.StrategyResult, err error) func(context.Context) (witness.StrategyResult, error) {
	return func(_ context.Context) (witness.StrategyResult, error) {
		result.Strategy = s
		return result, err
	}
}

func TestRunAudits_All(t *testing.T) {
	result1 := witness.StrategyResult{Strategy: witness.StrategyMFA}
	result2 := witness.StrategyResult{Strategy: witness.StrategyPatchOS}

	audits := []auditEntry{
		{witness.StrategyMFA, makeStubAudit(witness.StrategyMFA, result1, nil)},
		{witness.StrategyPatchOS, makeStubAudit(witness.StrategyPatchOS, result2, nil)},
	}

	results, nas, err := runAudits(context.Background(), audits, "all")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 2 {
		t.Errorf("expected 2 results, got %d", len(results))
	}
	if len(nas) != 0 {
		t.Errorf("expected 0 not-auditable, got %d", len(nas))
	}
}

func TestRunAudits_FilterByName(t *testing.T) {
	result1 := witness.StrategyResult{Strategy: witness.StrategyMFA}
	result2 := witness.StrategyResult{Strategy: witness.StrategyPatchOS}

	audits := []auditEntry{
		{witness.StrategyMFA, makeStubAudit(witness.StrategyMFA, result1, nil)},
		{witness.StrategyPatchOS, makeStubAudit(witness.StrategyPatchOS, result2, nil)},
	}

	results, _, err := runAudits(context.Background(), audits, "mfa")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("expected 1 result (mfa only), got %d", len(results))
	}
	if results[0].Strategy != witness.StrategyMFA {
		t.Errorf("expected StrategyMFA, got %s", results[0].Strategy)
	}
}

func TestRunAudits_ErrNotAuditable_AddedToNAs(t *testing.T) {
	audits := []auditEntry{
		{
			witness.StrategyMacroSettings,
			func(_ context.Context) (witness.StrategyResult, error) {
				return witness.StrategyResult{}, fmt.Errorf("wrap: %w", witness.ErrNotAuditable)
			},
		},
	}

	results, nas, err := runAudits(context.Background(), audits, "all")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
	if len(nas) != 1 || nas[0] != witness.StrategyMacroSettings {
		t.Errorf("expected StrategyMacroSettings in notAuditable, got %v", nas)
	}
}

func TestRunAudits_HardError_Propagated(t *testing.T) {
	hardErr := errors.New("network failure")
	audits := []auditEntry{
		{
			witness.StrategyMFA,
			func(_ context.Context) (witness.StrategyResult, error) {
				return witness.StrategyResult{}, hardErr
			},
		},
	}

	_, _, err := runAudits(context.Background(), audits, "all")
	if err == nil {
		t.Fatal("expected error to be propagated")
	}
	if !errors.Is(err, hardErr) {
		t.Errorf("expected hardErr to be in error chain, got: %v", err)
	}
}
