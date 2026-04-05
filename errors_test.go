package witness_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/e8evidence/witness"
)

func TestConsentRevokedError_401(t *testing.T) {
	err := &witness.ConsentRevokedError{TenantID: "acme", StatusCode: 401}
	msg := err.Error()
	if !strings.Contains(msg, "acme") {
		t.Errorf("expected error to contain 'acme', got: %s", msg)
	}
	if !strings.Contains(msg, "401") {
		t.Errorf("expected error to contain '401', got: %s", msg)
	}
}

func TestConsentRevokedError_403(t *testing.T) {
	err := &witness.ConsentRevokedError{TenantID: "acme", StatusCode: 403}
	msg := err.Error()
	if !strings.Contains(msg, "acme") {
		t.Errorf("expected error to contain 'acme', got: %s", msg)
	}
	if !strings.Contains(msg, "403") {
		t.Errorf("expected error to contain '403', got: %s", msg)
	}
}

func TestClaimsChallengeError(t *testing.T) {
	err := &witness.ClaimsChallengeError{
		Path:      "/users/me",
		Challenge: `Bearer realm="", claims="eyJhbGciOiJSUzI1NiJ9"`,
	}
	msg := err.Error()
	if !strings.Contains(msg, "/users/me") {
		t.Errorf("expected error to contain path '/users/me', got: %s", msg)
	}
	if !strings.Contains(msg, "claims=") {
		t.Errorf("expected error to contain 'claims=', got: %s", msg)
	}
}

func TestErrNotAuditable_WrapsCorrectly(t *testing.T) {
	wrapped := fmt.Errorf("wrap: %w", witness.ErrNotAuditable)
	if !errors.Is(wrapped, witness.ErrNotAuditable) {
		t.Error("expected errors.Is to find ErrNotAuditable in wrapped error")
	}
}

func TestConsentRevokedError_NotErrNotAuditable(t *testing.T) {
	err := &witness.ConsentRevokedError{}
	if errors.Is(err, witness.ErrNotAuditable) {
		t.Error("ConsentRevokedError should not match ErrNotAuditable")
	}
}
