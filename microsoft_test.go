package witness_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/e8evidence/witness"
)

// --- Constructor ---

func TestNewMSGraphClient_EmptyToken(t *testing.T) {
	creds := witness.MicrosoftCredentials{TenantID: "t", AccessToken: ""}
	_, err := witness.NewMSGraphClient(context.Background(), creds, discardLogger())
	if err == nil {
		t.Fatal("expected error for empty token")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "empty") {
		t.Errorf("expected error to mention 'empty', got: %v", err)
	}
}

func TestNewMSGraphClient_ValidToken(t *testing.T) {
	creds := witness.MicrosoftCredentials{TenantID: "t", AccessToken: "tok"}
	client, err := witness.NewMSGraphClient(context.Background(), creds, discardLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil client")
	}
}

// --- graphGet typed errors ---

func TestGraphGet_401_ConsentRevoked(t *testing.T) {
	srv := newFakeServer(t)
	srv.setGraphBase(t)

	srv.HandleFunc("/users", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})

	c := newMSClient(t, "tok", "tenant1")
	_, err := c.AuditMFA(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	var cre *witness.ConsentRevokedError
	if !errors.As(err, &cre) {
		t.Fatalf("expected *ConsentRevokedError, got %T: %v", err, err)
	}
	if cre.StatusCode != 401 {
		t.Errorf("expected StatusCode 401, got %d", cre.StatusCode)
	}
}

func TestGraphGet_403_NoClaimsChallenge_ConsentRevoked(t *testing.T) {
	srv := newFakeServer(t)
	srv.setGraphBase(t)

	srv.HandleFunc("/users", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})

	c := newMSClient(t, "tok", "tenant1")
	_, err := c.AuditMFA(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	var cre *witness.ConsentRevokedError
	if !errors.As(err, &cre) {
		t.Fatalf("expected *ConsentRevokedError, got %T: %v", err, err)
	}
	if cre.StatusCode != 403 {
		t.Errorf("expected StatusCode 403, got %d", cre.StatusCode)
	}
}

func TestGraphGet_403_WithClaimsChallenge_ClaimsChallengeError(t *testing.T) {
	srv := newFakeServer(t)
	srv.setGraphBase(t)

	srv.HandleFunc("/users", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="", claims="eyJhbGciOiJSUzI1NiJ9"`)
		w.WriteHeader(http.StatusForbidden)
	})

	c := newMSClient(t, "tok", "tenant1")
	_, err := c.AuditMFA(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	var cce *witness.ClaimsChallengeError
	if !errors.As(err, &cce) {
		t.Fatalf("expected *ClaimsChallengeError, got %T: %v", err, err)
	}
	if cce.Path == "" {
		t.Error("expected non-empty Path")
	}
	if !strings.Contains(cce.Challenge, "claims=") {
		t.Errorf("expected Challenge to contain 'claims=', got: %s", cce.Challenge)
	}
}

func TestGraphGet_500_GenericError(t *testing.T) {
	srv := newFakeServer(t)
	srv.setGraphBase(t)

	srv.HandleFunc("/users", statusHandler(http.StatusInternalServerError))

	c := newMSClient(t, "tok", "tenant1")
	_, err := c.AuditMFA(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	var cre *witness.ConsentRevokedError
	if errors.As(err, &cre) {
		t.Error("expected plain error, not ConsentRevokedError")
	}
}

// --- AuditMFA (Microsoft) ---

func TestMSAuditMFA_AllStrongMFA(t *testing.T) {
	srv := newFakeServer(t)
	srv.setGraphBase(t)

	srv.HandleFunc("/users", jsonHandler(map[string]any{
		"value": []map[string]any{
			{"id": "u1", "userPrincipalName": "user1@example.com"},
		},
	}))

	srv.HandleFunc("/users/u1/authentication/methods", jsonHandler(map[string]any{
		"value": []map[string]any{
			{"@odata.type": "#microsoft.graph.fido2AuthenticationMethod"},
		},
	}))

	c := newMSClient(t, "tok", "tenant1")
	result, err := c.AuditMFA(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range result.Findings {
		if !f.Passed {
			t.Errorf("expected all findings to pass, got: %+v", f)
		}
	}
}

func TestMSAuditMFA_UserLacksStrongMFA(t *testing.T) {
	srv := newFakeServer(t)
	srv.setGraphBase(t)

	srv.HandleFunc("/users", jsonHandler(map[string]any{
		"value": []map[string]any{
			{"id": "u1", "userPrincipalName": "user1@example.com"},
		},
	}))

	srv.HandleFunc("/users/u1/authentication/methods", jsonHandler(map[string]any{
		"value": []map[string]any{
			{"@odata.type": "#microsoft.graph.passwordAuthenticationMethod"},
		},
	}))

	c := newMSClient(t, "tok", "tenant1")
	result, err := c.AuditMFA(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 || result.Findings[0].Passed {
		t.Error("expected one failing finding for password-only auth")
	}
}

func TestMSAuditMFA_WindowsHelloCountsAsStrong(t *testing.T) {
	srv := newFakeServer(t)
	srv.setGraphBase(t)

	srv.HandleFunc("/users", jsonHandler(map[string]any{
		"value": []map[string]any{
			{"id": "u1", "userPrincipalName": "user1@example.com"},
		},
	}))

	srv.HandleFunc("/users/u1/authentication/methods", jsonHandler(map[string]any{
		"value": []map[string]any{
			{"@odata.type": "#microsoft.graph.windowsHelloForBusinessAuthenticationMethod"},
		},
	}))

	c := newMSClient(t, "tok", "tenant1")
	result, err := c.AuditMFA(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range result.Findings {
		if !f.Passed {
			t.Errorf("expected Windows Hello to count as strong MFA: %+v", f)
		}
	}
}

func TestMSAuditMFA_AuthMethodsError_UserSkipped(t *testing.T) {
	srv := newFakeServer(t)
	srv.setGraphBase(t)

	srv.HandleFunc("/users", jsonHandler(map[string]any{
		"value": []map[string]any{
			{"id": "u1", "userPrincipalName": "user1@example.com"},
		},
	}))

	srv.HandleFunc("/users/u1/authentication/methods", statusHandler(http.StatusInternalServerError))

	c := newMSClient(t, "tok", "tenant1")
	result, err := c.AuditMFA(context.Background())
	if err != nil {
		t.Fatalf("expected no hard error for user skip, got: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings (user skipped), got %d", len(result.Findings))
	}
}

func TestMSAuditMFA_EmptyUserList(t *testing.T) {
	srv := newFakeServer(t)
	srv.setGraphBase(t)

	srv.HandleJSON("/users", map[string]any{"value": []any{}})

	c := newMSClient(t, "tok", "tenant1")
	result, err := c.AuditMFA(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(result.Findings))
	}
}

// --- AuditPatching ---

func TestMSAuditPatching_AllCompliant(t *testing.T) {
	srv := newFakeServer(t)
	srv.setGraphBase(t)

	lastSync := time.Now().UTC().Add(-3 * 24 * time.Hour).Format(time.RFC3339)
	srv.HandleJSON("/deviceManagement/managedDevices", map[string]any{
		"value": []map[string]any{
			{"id": "d1", "osVersion": "10.0.19044", "lastSyncDateTime": lastSync},
		},
	})

	c := newMSClient(t, "tok", "tenant1")
	result, err := c.AuditPatching(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range result.Findings {
		if !f.Passed {
			t.Errorf("expected all compliant, got: %+v", f)
		}
	}
}

func TestMSAuditPatching_DeviceStale(t *testing.T) {
	srv := newFakeServer(t)
	srv.setGraphBase(t)

	lastSync := time.Now().UTC().Add(-20 * 24 * time.Hour).Format(time.RFC3339)
	srv.HandleJSON("/deviceManagement/managedDevices", map[string]any{
		"value": []map[string]any{
			{"id": "d1", "osVersion": "10.0.19044", "lastSyncDateTime": lastSync},
		},
	})

	c := newMSClient(t, "tok", "tenant1")
	result, err := c.AuditPatching(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 || result.Findings[0].Passed {
		t.Error("expected one failing finding for stale device")
	}
}

func TestMSAuditPatching_InvalidDatetime_Fails(t *testing.T) {
	srv := newFakeServer(t)
	srv.setGraphBase(t)

	srv.HandleJSON("/deviceManagement/managedDevices", map[string]any{
		"value": []map[string]any{
			{"id": "d1", "osVersion": "10.0.19044", "lastSyncDateTime": ""},
		},
	})

	c := newMSClient(t, "tok", "tenant1")
	result, err := c.AuditPatching(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Zero time is before cutoff => fails (conservative)
	if len(result.Findings) != 1 || result.Findings[0].Passed {
		t.Error("expected one failing finding for empty lastSyncDateTime")
	}
}

// --- AuditAdminRoles ---
//
// NOTE: The Microsoft Graph API uses URLs with spaces in query parameters
// (e.g. "$filter=roleDefinitionId eq '...'"). Go's net/http server returns
// 400 Bad Request for such URLs, so AuditAdminRoles tests use a custom
// transport (newMSClientWithMux) that bypasses HTTP parsing and routes
// directly through the mux's ServeHTTP.

func newAdminRolesMux(t *testing.T, roleHandler, methodHandler http.HandlerFunc) (*http.ServeMux, *witness.MSGraphClient) {
	t.Helper()
	mux := http.NewServeMux()
	if roleHandler != nil {
		mux.HandleFunc("/roleManagement/directory/roleAssignments", roleHandler)
	}
	if methodHandler != nil {
		mux.HandleFunc("/users/u1/authentication/methods", methodHandler)
	}
	c := newMSClientWithMux(t, "tok", "tenant1", mux)
	return mux, c
}

func TestMSAuditAdminRoles_GlobalAdmin_WithFIDO2(t *testing.T) {
	_, c := newAdminRolesMux(t,
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			// r.URL.RawQuery contains the full query; check for the Global Admin role ID
			if strings.Contains(r.URL.RawQuery, "62e90394") {
				fmt.Fprint(w, `{"value":[{"principalId":"u1","principal":{"id":"u1","userPrincipalName":"admin@example.com"}}]}`)
			} else {
				fmt.Fprint(w, `{"value":[]}`)
			}
		},
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"value":[{"@odata.type":"#microsoft.graph.fido2AuthenticationMethod"}]}`)
		},
	)
	result, err := c.AuditAdminRoles(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 || !result.Findings[0].Passed {
		t.Errorf("expected 1 passing finding, got %d findings", len(result.Findings))
	}
}

func TestMSAuditAdminRoles_GlobalAdmin_NoStrongMFA(t *testing.T) {
	_, c := newAdminRolesMux(t,
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if strings.Contains(r.URL.RawQuery, "62e90394") {
				fmt.Fprint(w, `{"value":[{"principalId":"u1","principal":{"id":"u1","userPrincipalName":"admin@example.com"}}]}`)
			} else {
				fmt.Fprint(w, `{"value":[]}`)
			}
		},
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"value":[{"@odata.type":"#microsoft.graph.passwordAuthenticationMethod"}]}`)
		},
	)
	result, err := c.AuditAdminRoles(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 || result.Findings[0].Passed {
		t.Error("expected one failing finding for admin without strong MFA")
	}
}

func TestMSAuditAdminRoles_DuplicatePrincipal_DeduplicatedAcrossRoles(t *testing.T) {
	// Same principal returned by all role queries
	_, c := newAdminRolesMux(t,
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"value":[{"principalId":"u1","principal":{"id":"u1","userPrincipalName":"admin@example.com"}}]}`)
		},
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"value":[{"@odata.type":"#microsoft.graph.fido2AuthenticationMethod"}]}`)
		},
	)
	result, err := c.AuditAdminRoles(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Errorf("expected exactly 1 finding (deduplication), got %d", len(result.Findings))
	}
}

func TestMSAuditAdminRoles_NullPrincipal_Skipped(t *testing.T) {
	_, c := newAdminRolesMux(t,
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"value":[{"principalId":"u1","principal":null}]}`)
		},
		nil,
	)
	result, err := c.AuditAdminRoles(context.Background())
	if err != nil {
		t.Fatalf("expected no panic/error for null principal, got: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings for null principal, got %d", len(result.Findings))
	}
}

func TestMSAuditAdminRoles_NoAssignments(t *testing.T) {
	_, c := newAdminRolesMux(t,
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"value":[]}`)
		},
		nil,
	)
	result, err := c.AuditAdminRoles(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(result.Findings))
	}
	if result.Level != witness.ML3 {
		t.Errorf("expected ML3 for no assignments, got %s", result.Level)
	}
}
