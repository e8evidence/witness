package witness_test

import (
	"testing"

	"github.com/e8evidence/witness"
)

func TestMaturityLevel_String(t *testing.T) {
	tests := []struct {
		level witness.MaturityLevel
		want  string
	}{
		{witness.ML0, "ML0"},
		{witness.ML1, "ML1"},
		{witness.ML2, "ML2"},
		{witness.ML3, "ML3"},
	}
	for _, tc := range tests {
		if got := tc.level.String(); got != tc.want {
			t.Errorf("MaturityLevel(%d).String() = %q, want %q", tc.level, got, tc.want)
		}
	}
}

func TestMaturityLevel_TrafficLight(t *testing.T) {
	tests := []struct {
		level witness.MaturityLevel
		want  string
	}{
		{witness.ML3, "green"},
		{witness.ML2, "amber"},
		{witness.ML1, "red"},
		{witness.ML0, "red"},
		{witness.MaturityLevel(99), "red"},
	}
	for _, tc := range tests {
		if got := tc.level.TrafficLight(); got != tc.want {
			t.Errorf("MaturityLevel(%d).TrafficLight() = %q, want %q", tc.level, got, tc.want)
		}
	}
}

func TestAllStrategies_Length(t *testing.T) {
	if got := len(witness.AllStrategies); got != 8 {
		t.Errorf("len(AllStrategies) = %d, want 8", got)
	}
}

func TestISMControl_AllStrategiesHaveRefs(t *testing.T) {
	for _, s := range witness.AllStrategies {
		refs, ok := witness.ISMControl[s]
		if !ok {
			t.Errorf("strategy %q not found in ISMControl", s)
			continue
		}
		if len(refs) == 0 {
			t.Errorf("strategy %q has empty ISMControl refs", s)
		}
	}
}
