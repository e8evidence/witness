package witness_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/e8evidence/witness"
)

// --- NewGoogleWorkspaceClient token exchange ---

func TestNewGoogleWorkspaceClient_AccessTokenDirect(t *testing.T) {
	// With AccessToken set, no token exchange is performed.
	creds := witness.GoogleCredentials{
		CustomerID:  "C0test",
		AccessToken: "pre-tok",
	}
	client, err := witness.NewGoogleWorkspaceClient(context.Background(), creds, discardLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil client")
	}
}

func TestNewGoogleWorkspaceClient_RefreshTokenExchange_Success(t *testing.T) {
	srv := newFakeServer(t)
	srv.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token":"fresh"}`))
	})
	srv.setTokenURL(t)

	creds := witness.GoogleCredentials{
		CustomerID:   "C0test",
		RefreshToken: "my-refresh",
		ClientID:     "cid",
		ClientSecret: "csec",
	}
	client, err := witness.NewGoogleWorkspaceClient(context.Background(), creds, discardLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil client")
	}
}

func TestNewGoogleWorkspaceClient_RefreshTokenExchange_HTTP400(t *testing.T) {
	srv := newFakeServer(t)
	srv.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad request", http.StatusBadRequest)
	})
	srv.setTokenURL(t)

	creds := witness.GoogleCredentials{
		CustomerID:   "C0test",
		RefreshToken: "my-refresh",
		ClientID:     "cid",
		ClientSecret: "csec",
	}
	_, err := witness.NewGoogleWorkspaceClient(context.Background(), creds, discardLogger())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestNewGoogleWorkspaceClient_RefreshTokenExchange_BadJSON(t *testing.T) {
	srv := newFakeServer(t)
	srv.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("not-json"))
	})
	srv.setTokenURL(t)

	creds := witness.GoogleCredentials{
		CustomerID:   "C0test",
		RefreshToken: "my-refresh",
		ClientID:     "cid",
		ClientSecret: "csec",
	}
	_, err := witness.NewGoogleWorkspaceClient(context.Background(), creds, discardLogger())
	if err == nil {
		t.Fatal("expected error for bad JSON, got nil")
	}
}

// --- AuditMFA (Google) ---

func TestAuditMFA_AllEnrolled(t *testing.T) {
	srv := newFakeServer(t)
	srv.setAdminBase(t)

	srv.HandleJSON("/users", map[string]any{
		"users": []map[string]any{
			{"primaryEmail": "a@example.com", "isEnrolledIn2Sv": true, "isAdmin": false},
			{"primaryEmail": "b@example.com", "isEnrolledIn2Sv": true, "isAdmin": false},
		},
	})

	c := newGoogleClient(t, "tok", "C0test")
	result, err := c.AuditMFA(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(result.Findings))
	}
	for _, f := range result.Findings {
		if !f.Passed {
			t.Errorf("expected all findings to pass, got: %v", f)
		}
	}
}

func TestAuditMFA_OneMissing2SV(t *testing.T) {
	srv := newFakeServer(t)
	srv.setAdminBase(t)

	srv.HandleJSON("/users", map[string]any{
		"users": []map[string]any{
			{"primaryEmail": "a@example.com", "isEnrolledIn2Sv": true, "isAdmin": false},
			{"primaryEmail": "b@example.com", "isEnrolledIn2Sv": false, "isAdmin": false},
		},
	})

	c := newGoogleClient(t, "tok", "C0test")
	result, err := c.AuditMFA(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	failCount := 0
	for _, f := range result.Findings {
		if !f.Passed {
			failCount++
			if f.Control != "ISM-1504" {
				t.Errorf("expected control ISM-1504, got %s", f.Control)
			}
		}
	}
	if failCount != 1 {
		t.Errorf("expected 1 failing finding, got %d", failCount)
	}
}

func TestAuditMFA_EmptyUserList(t *testing.T) {
	srv := newFakeServer(t)
	srv.setAdminBase(t)

	srv.HandleJSON("/users", map[string]any{"users": []any{}})

	c := newGoogleClient(t, "tok", "C0test")
	result, err := c.AuditMFA(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(result.Findings))
	}
}

func TestAuditMFA_Pagination(t *testing.T) {
	srv := newFakeServer(t)
	srv.setAdminBase(t)

	srv.HandleFunc("/users", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		pageToken := r.URL.Query().Get("pageToken")
		if pageToken == "" {
			w.Write([]byte(`{"users":[{"primaryEmail":"a@example.com","isEnrolledIn2Sv":true}],"nextPageToken":"tok2"}`))
		} else if pageToken == "tok2" {
			w.Write([]byte(`{"users":[{"primaryEmail":"b@example.com","isEnrolledIn2Sv":true}]}`))
		} else {
			http.Error(w, "unexpected page token", http.StatusBadRequest)
		}
	})

	c := newGoogleClient(t, "tok", "C0test")
	result, err := c.AuditMFA(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 2 {
		t.Errorf("expected 2 findings (from 2 pages), got %d", len(result.Findings))
	}
}

func TestAuditMFA_APIError(t *testing.T) {
	srv := newFakeServer(t)
	srv.setAdminBase(t)

	srv.HandleFunc("/users", statusHandler(http.StatusInternalServerError))

	c := newGoogleClient(t, "tok", "C0test")
	_, err := c.AuditMFA(context.Background())
	if err == nil {
		t.Fatal("expected error from 500, got nil")
	}
}

func TestAuditMFA_NoPIIInDescriptions(t *testing.T) {
	srv := newFakeServer(t)
	srv.setAdminBase(t)

	srv.HandleJSON("/users", map[string]any{
		"users": []map[string]any{
			{"primaryEmail": "user@example.com", "isEnrolledIn2Sv": true, "isAdmin": false},
		},
	})

	c := newGoogleClient(t, "tok", "C0test")
	result, err := c.AuditMFA(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range result.Findings {
		if strings.Contains(f.Description, "user@example.com") {
			t.Errorf("description contains raw email PII: %s", f.Description)
		}
	}
}

// --- AuditPrivileges ---

func TestAuditPrivileges_AllHave2SV(t *testing.T) {
	srv := newFakeServer(t)
	srv.setAdminBase(t)

	srv.HandleJSON("/users", map[string]any{
		"users": []map[string]any{
			{"primaryEmail": "admin@example.com", "isEnrolledIn2Sv": true, "isAdmin": true},
		},
	})

	c := newGoogleClient(t, "tok", "C0test")
	result, err := c.AuditPrivileges(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range result.Findings {
		if !f.Passed {
			t.Errorf("expected all findings to pass, got: %v", f)
		}
		if f.Control != "ISM-1507" {
			t.Errorf("expected control ISM-1507, got %s", f.Control)
		}
	}
}

func TestAuditPrivileges_Missing2SV(t *testing.T) {
	srv := newFakeServer(t)
	srv.setAdminBase(t)

	srv.HandleJSON("/users", map[string]any{
		"users": []map[string]any{
			{"primaryEmail": "admin@example.com", "isEnrolledIn2Sv": false, "isAdmin": true},
		},
	})

	c := newGoogleClient(t, "tok", "C0test")
	result, err := c.AuditPrivileges(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	if result.Findings[0].Passed {
		t.Error("expected finding to fail")
	}
	if result.Findings[0].Control != "ISM-1507" {
		t.Errorf("expected control ISM-1507, got %s", result.Findings[0].Control)
	}
}

func TestAuditPrivileges_NoAdmins(t *testing.T) {
	srv := newFakeServer(t)
	srv.setAdminBase(t)

	srv.HandleJSON("/users", map[string]any{"users": []any{}})

	c := newGoogleClient(t, "tok", "C0test")
	result, err := c.AuditPrivileges(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(result.Findings))
	}
}

// --- AuditChrome ---

func TestAuditChrome_AllSameVersion(t *testing.T) {
	srv := newFakeServer(t)
	srv.setAdminBase(t)
	srv.setChromeMgmtBase(t)

	srv.HandleJSON("/customers/C0test/reports:countBrowserVersions", map[string]any{
		"browserVersions": []map[string]any{
			{"version": "124.0.6367.82", "count": "10", "channel": "STABLE", "system": "WINDOWS"},
		},
	})

	c := newGoogleClient(t, "tok", "C0test")
	result, err := c.AuditChrome(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range result.Findings {
		if !f.Passed {
			t.Errorf("expected all findings to pass, got: %v", f)
		}
	}
}

func TestAuditChrome_MixedVersions(t *testing.T) {
	srv := newFakeServer(t)
	srv.setAdminBase(t)
	srv.setChromeMgmtBase(t)

	srv.HandleJSON("/customers/C0test/reports:countBrowserVersions", map[string]any{
		"browserVersions": []map[string]any{
			{"version": "123.0.6312.86", "count": "5", "channel": "STABLE", "system": "WINDOWS"},
			{"version": "124.0.6367.82", "count": "10", "channel": "STABLE", "system": "WINDOWS"},
		},
	})

	c := newGoogleClient(t, "tok", "C0test")
	result, err := c.AuditChrome(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	pass, fail := 0, 0
	for _, f := range result.Findings {
		if f.Passed {
			pass++
		} else {
			fail++
		}
	}
	if pass != 1 || fail != 1 {
		t.Errorf("expected 1 pass and 1 fail, got pass=%d fail=%d", pass, fail)
	}
}

func TestAuditChrome_NoBrowsers_HTTP403(t *testing.T) {
	srv := newFakeServer(t)
	srv.setAdminBase(t)
	srv.setChromeMgmtBase(t)

	srv.HandleFunc("/customers/C0test/reports:countBrowserVersions", statusHandler(http.StatusForbidden))

	c := newGoogleClient(t, "tok", "C0test")
	_, err := c.AuditChrome(context.Background())
	if !errors.Is(err, witness.ErrNotAuditable) {
		t.Errorf("expected ErrNotAuditable, got: %v", err)
	}
}

func TestAuditChrome_NoBrowsers_EmptyResponse(t *testing.T) {
	srv := newFakeServer(t)
	srv.setAdminBase(t)
	srv.setChromeMgmtBase(t)

	srv.HandleJSON("/customers/C0test/reports:countBrowserVersions", map[string]any{
		"browserVersions": []any{},
	})

	c := newGoogleClient(t, "tok", "C0test")
	_, err := c.AuditChrome(context.Background())
	if !errors.Is(err, witness.ErrNotAuditable) {
		t.Errorf("expected ErrNotAuditable, got: %v", err)
	}
}

func TestAuditChrome_Pagination(t *testing.T) {
	srv := newFakeServer(t)
	srv.setAdminBase(t)
	srv.setChromeMgmtBase(t)

	srv.HandleFunc("/customers/C0test/reports:countBrowserVersions", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		pageToken := r.URL.Query().Get("pageToken")
		if pageToken == "" {
			w.Write([]byte(`{"browserVersions":[{"version":"124.0.6367.82","count":"5","channel":"STABLE","system":"WINDOWS"}],"nextPageToken":"p2"}`))
		} else if pageToken == "p2" {
			w.Write([]byte(`{"browserVersions":[{"version":"124.0.6367.82","count":"3","channel":"STABLE","system":"MAC"}]}`))
		} else {
			http.Error(w, "unexpected page token", http.StatusBadRequest)
		}
	})

	c := newGoogleClient(t, "tok", "C0test")
	result, err := c.AuditChrome(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 2 {
		t.Errorf("expected 2 findings from 2 pages, got %d", len(result.Findings))
	}
}

// --- AuditBackups ---

func TestAuditBackups_ImmutableVendorAndVault(t *testing.T) {
	srv := newFakeServer(t)
	srv.setAdminBase(t)
	srv.setVaultBase(t)

	// Admin users (for detectBackupVendor's listSuperAdmins call)
	srv.HandleFunc("/users", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		q := r.URL.Query().Get("query")
		if strings.Contains(q, "isAdmin") {
			w.Write([]byte(`{"users":[{"primaryEmail":"admin@example.com","isAdmin":true}]}`))
		} else {
			w.Write([]byte(`{"users":[]}`))
		}
	})

	// Token endpoint for admin user
	srv.HandleFunc("/users/admin@example.com/tokens", jsonHandler(map[string]any{
		"items": []map[string]any{
			{
				"displayText": "Afi.ai Backup",
				"clientId":    "client123",
				"scopes":      []string{"https://www.googleapis.com/auth/drive"},
			},
		},
	}))

	// Vault matters
	srv.HandleJSON("/matters", map[string]any{
		"matters": []map[string]any{
			{"matterId": "m1", "name": "Litigation Hold", "state": "OPEN"},
		},
	})

	c := newGoogleClient(t, "tok", "C0test")
	result, err := c.AuditBackups(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(result.Findings))
	}
	for _, f := range result.Findings {
		if !f.Passed {
			t.Errorf("expected all findings to pass, got: %+v", f)
		}
	}
	scorer := witness.NewScorer(discardLogger())
	score := scorer.Score("t", "t", []witness.StrategyResult{result}, witness.ML0)
	if score.Strategies[0].Level != witness.ML3 {
		t.Errorf("expected ML3, got %s", score.Strategies[0].Level)
	}
}

func TestAuditBackups_NonImmutableVendor_NoVault(t *testing.T) {
	srv := newFakeServer(t)
	srv.setAdminBase(t)
	srv.setVaultBase(t)

	srv.HandleFunc("/users", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		q := r.URL.Query().Get("query")
		if strings.Contains(q, "isAdmin") {
			w.Write([]byte(`{"users":[{"primaryEmail":"admin@example.com","isAdmin":true}]}`))
		} else {
			w.Write([]byte(`{"users":[]}`))
		}
	})

	srv.HandleFunc("/users/admin@example.com/tokens", jsonHandler(map[string]any{
		"items": []map[string]any{
			{
				"displayText": "Dropsuite",
				"clientId":    "client123",
				"scopes":      []string{"https://www.googleapis.com/auth/drive"},
			},
		},
	}))

	// Vault returns 403 (not licensed)
	srv.HandleFunc("/matters", statusHandler(http.StatusForbidden))

	c := newGoogleClient(t, "tok", "C0test")
	result, err := c.AuditBackups(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(result.Findings))
	}
	// vendor pass, immutable fail, vault fail => ML1
	scorer := witness.NewScorer(discardLogger())
	score := scorer.Score("t", "t", []witness.StrategyResult{result}, witness.ML0)
	if score.Strategies[0].Level != witness.ML1 {
		t.Errorf("expected ML1, got %s", score.Strategies[0].Level)
	}
}

func TestAuditBackups_NoVendorNoVault(t *testing.T) {
	srv := newFakeServer(t)
	srv.setAdminBase(t)
	srv.setVaultBase(t)

	srv.HandleFunc("/users", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"users":[]}`))
	})

	srv.HandleFunc("/matters", statusHandler(http.StatusForbidden))

	c := newGoogleClient(t, "tok", "C0test")
	result, err := c.AuditBackups(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range result.Findings {
		if f.Passed {
			t.Errorf("expected all findings to fail, got passing: %+v", f)
		}
	}
	scorer := witness.NewScorer(discardLogger())
	score := scorer.Score("t", "t", []witness.StrategyResult{result}, witness.ML0)
	if score.Strategies[0].Level != witness.ML0 {
		t.Errorf("expected ML0, got %s", score.Strategies[0].Level)
	}
}

func TestAuditBackups_VendorMatchCaseInsensitive(t *testing.T) {
	srv := newFakeServer(t)
	srv.setAdminBase(t)
	srv.setVaultBase(t)

	srv.HandleFunc("/users", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		q := r.URL.Query().Get("query")
		if strings.Contains(q, "isAdmin") {
			w.Write([]byte(`{"users":[{"primaryEmail":"admin@example.com","isAdmin":true}]}`))
		} else {
			w.Write([]byte(`{"users":[]}`))
		}
	})

	// Uppercase AFI.AI should still match
	srv.HandleFunc("/users/admin@example.com/tokens", jsonHandler(map[string]any{
		"items": []map[string]any{
			{
				"displayText": "AFI.AI",
				"clientId":    "client123",
				"scopes":      []string{"https://www.googleapis.com/auth/drive"},
			},
		},
	}))

	srv.HandleFunc("/matters", statusHandler(http.StatusForbidden))

	c := newGoogleClient(t, "tok", "C0test")
	result, err := c.AuditBackups(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// First finding (vendor detected) should pass
	if len(result.Findings) < 1 || !result.Findings[0].Passed {
		t.Errorf("expected vendor finding to pass (case-insensitive match)")
	}
}

func TestAuditBackups_TokenMissingBackupScope(t *testing.T) {
	srv := newFakeServer(t)
	srv.setAdminBase(t)
	srv.setVaultBase(t)

	srv.HandleFunc("/users", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		q := r.URL.Query().Get("query")
		if strings.Contains(q, "isAdmin") {
			w.Write([]byte(`{"users":[{"primaryEmail":"admin@example.com","isAdmin":true}]}`))
		} else {
			w.Write([]byte(`{"users":[]}`))
		}
	})

	// Token has "afi" in display name but wrong scope
	srv.HandleFunc("/users/admin@example.com/tokens", jsonHandler(map[string]any{
		"items": []map[string]any{
			{
				"displayText": "afi",
				"clientId":    "client123",
				"scopes":      []string{"https://www.googleapis.com/auth/calendar"},
			},
		},
	}))

	srv.HandleFunc("/matters", statusHandler(http.StatusForbidden))

	c := newGoogleClient(t, "tok", "C0test")
	result, err := c.AuditBackups(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// No vendor match — first finding should fail
	if len(result.Findings) < 1 || result.Findings[0].Passed {
		t.Errorf("expected vendor finding to fail (missing backup scope)")
	}
}

func TestAuditBackups_VaultHTTP403_NotLicensed(t *testing.T) {
	srv := newFakeServer(t)
	srv.setAdminBase(t)
	srv.setVaultBase(t)

	srv.HandleFunc("/users", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"users":[]}`))
	})

	// Vault returns 403 — should NOT cause a hard error from AuditBackups
	srv.HandleFunc("/matters", statusHandler(http.StatusForbidden))

	c := newGoogleClient(t, "tok", "C0test")
	result, err := c.AuditBackups(context.Background())
	if err != nil {
		t.Fatalf("vault 403 should not cause hard error, got: %v", err)
	}
	// Vault finding should fail
	vaultFinding := result.Findings[2]
	if vaultFinding.Passed {
		t.Error("expected vault finding to fail when 403")
	}
}
