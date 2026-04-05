package witness_test

import (
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/e8evidence/witness"
)

// ---- HashPII ----------------------------------------------------------------

func TestHashPII_Deterministic(t *testing.T) {
	h1 := witness.HashPII("user@example.com")
	h2 := witness.HashPII("user@example.com")
	if h1 != h2 {
		t.Fatalf("HashPII not deterministic: %q != %q", h1, h2)
	}
}

func TestHashPII_DifferentInputs(t *testing.T) {
	if witness.HashPII("a@b.com") == witness.HashPII("c@d.com") {
		t.Fatal("HashPII collision on distinct inputs")
	}
}

func TestHashPII_IsHex(t *testing.T) {
	h := witness.HashPII("test")
	if len(h) != 64 {
		t.Fatalf("HashPII length = %d, want 64", len(h))
	}
	for _, r := range h {
		if !strings.ContainsRune("0123456789abcdef", r) {
			t.Fatalf("HashPII produced non-hex character %q in %q", r, h)
		}
	}
}

// ---- MarshalFindings --------------------------------------------------------

func TestMarshalFindings_RoundTrip(t *testing.T) {
	findings := []witness.Finding{
		{UserHash: "abc123", Description: "MFA enabled", Control: "ISM-1504", Passed: true},
		{UserHash: "def456", Description: "No FIDO2", Control: "ISM-1679", Passed: false, Evidence: `{"method":"sms"}`},
	}

	raw, err := witness.MarshalFindings(findings)
	if err != nil {
		t.Fatalf("MarshalFindings: %v", err)
	}

	var got []witness.Finding
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if diff := cmp.Diff(findings, got); diff != "" {
		t.Fatalf("round-trip mismatch (-want +got):\n%s", diff)
	}
}

func TestMarshalFindings_Empty(t *testing.T) {
	raw, err := witness.MarshalFindings(nil)
	if err != nil {
		t.Fatalf("MarshalFindings(nil): %v", err)
	}
	if raw != "null" {
		t.Fatalf("expected \"null\", got %q", raw)
	}
}

// ---- Scorer / weakest-link --------------------------------------------------

func makeResult(strategy witness.Strategy, findings ...witness.Finding) witness.StrategyResult {
	return witness.BuildStrategyResult(strategy, findings)
}

func passed(ctrl string) witness.Finding { return witness.Finding{Control: ctrl, Passed: true} }
func failed(ctrl string) witness.Finding { return witness.Finding{Control: ctrl, Passed: false} }

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestScore_WeakestLink(t *testing.T) {
	scorer := witness.NewScorer(discardLogger())

	cases := []struct {
		name     string
		results  []witness.StrategyResult
		previous witness.MaturityLevel
		wantML   witness.MaturityLevel
		drifted  bool
	}{
		{
			name:    "all passing → ML3",
			results: []witness.StrategyResult{makeResult(witness.StrategyMFA, passed("ISM-1504"))},
			wantML:  witness.ML3,
		},
		{
			name:    "one fail → ML2",
			results: []witness.StrategyResult{makeResult(witness.StrategyMFA, passed("ISM-1504"), failed("ISM-1679"))},
			wantML:  witness.ML2,
		},
		{
			name:    "two fails → ML1",
			results: []witness.StrategyResult{makeResult(witness.StrategyMFA, failed("ISM-1504"), failed("ISM-1679"))},
			wantML:  witness.ML1,
		},
		{
			name: "three fails → ML0",
			results: []witness.StrategyResult{
				makeResult(witness.StrategyMFA, failed("ISM-1504"), failed("ISM-1679"), failed("ISM-1175")),
			},
			wantML: witness.ML0,
		},
		{
			name: "weakest strategy drags overall",
			results: []witness.StrategyResult{
				makeResult(witness.StrategyMFA, passed("ISM-1504")),                               // ML3
				makeResult(witness.StrategyPatchOS, failed("ISM-1876")),                           // ML2
				makeResult(witness.StrategyRestrictAdmin, failed("ISM-1507"), failed("ISM-1175")), // ML1
			},
			wantML: witness.ML1, // weakest link
		},
		{
			name:     "drift detected when previous differs",
			results:  []witness.StrategyResult{makeResult(witness.StrategyMFA, failed("ISM-1504"))},
			previous: witness.ML3,
			wantML:   witness.ML2,
			drifted:  true,
		},
		{
			name:     "no drift when previous is 0 (first scan)",
			results:  []witness.StrategyResult{makeResult(witness.StrategyMFA, failed("ISM-1504"))},
			previous: witness.ML0,
			wantML:   witness.ML2,
			drifted:  false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			score := scorer.Score("tenant-1", "Tenant One", tc.results, tc.previous)
			if score.Overall != tc.wantML {
				t.Errorf("Overall = %s, want %s", score.Overall, tc.wantML)
			}
			if score.Drifted != tc.drifted {
				t.Errorf("Drifted = %v, want %v", score.Drifted, tc.drifted)
			}
		})
	}
}

func TestScore_MultipleStrategies_IndividualLevels(t *testing.T) {
	scorer := witness.NewScorer(discardLogger())

	results := []witness.StrategyResult{
		makeResult(witness.StrategyMFA, passed("ISM-1504")),
		makeResult(witness.StrategyPatchOS, failed("ISM-1876"), failed("ISM-1877")),
	}
	score := scorer.Score("t", "T", results, witness.ML0)

	if score.Strategies[0].Level != witness.ML3 {
		t.Errorf("MFA strategy = %s, want ML3", score.Strategies[0].Level)
	}
	if score.Strategies[1].Level != witness.ML1 {
		t.Errorf("PatchOS strategy = %s, want ML1", score.Strategies[1].Level)
	}
	if score.Overall != witness.ML1 {
		t.Errorf("Overall = %s, want ML1", score.Overall)
	}
}
