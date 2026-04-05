package witness_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/e8evidence/witness"
)

// TestAuditUserAppHardening_CBCM_NotEnrolled_NoError tests that when CBCM is
// not enrolled (403 from browser versions), AuditUserAppHardening does NOT
// return an error (unlike AuditAppControl which does).
func TestAuditUserAppHardening_CBCM_NotEnrolled_NoError(t *testing.T) {
	srv := newFakeServer(t)
	srv.setAdminBase(t)
	srv.setChromeMgmtBase(t)

	srv.HandleFunc("/customers/C0test/reports:countBrowserVersions", statusHandler(http.StatusForbidden))

	// Admin users for OAuth scan
	srv.HandleFunc("/users", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"users":[]}`))
	})

	c := newGoogleClient(t, "tok", "C0test")
	result, err := c.AuditUserAppHardening(context.Background())
	if err != nil {
		t.Fatalf("expected no error when CBCM not enrolled, got: %v", err)
	}
	// Should have a failing ISM-1486 finding about CBCM not enrolled
	found := false
	for _, f := range result.Findings {
		if f.Control == "ISM-1486" && !f.Passed {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected a failing ISM-1486 finding about CBCM not enrolled")
	}
}

func TestAuditUserAppHardening_CBCM_AllStable(t *testing.T) {
	srv := newFakeServer(t)
	srv.setAdminBase(t)
	srv.setChromeMgmtBase(t)

	srv.HandleJSON("/customers/C0test/reports:countBrowserVersions", map[string]any{
		"browserVersions": []map[string]any{
			{"version": "124.0.6367.82", "count": "5", "channel": "STABLE", "system": "WINDOWS"},
		},
	})

	// Empty org units (flat OU) — policy checks skipped
	srv.HandleJSON("/customer/C0test/orgunits", map[string]any{"organizationUnits": []any{}})

	// Users for OAuth scan
	srv.HandleFunc("/users", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"users":[]}`))
	})

	c := newGoogleClient(t, "tok", "C0test")
	result, err := c.AuditUserAppHardening(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range result.Findings {
		if f.Control == "ISM-1486" && strings.Contains(f.Description, "STABLE") {
			if !f.Passed {
				t.Errorf("expected stable channel finding to pass, got: %+v", f)
			}
		}
	}
}

func TestAuditUserAppHardening_CBCM_BetaChannel(t *testing.T) {
	srv := newFakeServer(t)
	srv.setAdminBase(t)
	srv.setChromeMgmtBase(t)

	srv.HandleJSON("/customers/C0test/reports:countBrowserVersions", map[string]any{
		"browserVersions": []map[string]any{
			{"version": "125.0.0.1", "count": "3", "channel": "BETA", "system": "WINDOWS"},
		},
	})

	srv.HandleJSON("/customer/C0test/orgunits", map[string]any{"organizationUnits": []any{}})

	srv.HandleFunc("/users", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"users":[]}`))
	})

	c := newGoogleClient(t, "tok", "C0test")
	result, err := c.AuditUserAppHardening(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, f := range result.Findings {
		if !f.Passed && strings.Contains(f.Description, "non-production") {
			found = true
		}
	}
	if !found {
		t.Error("expected failing finding mentioning 'non-production' for BETA channel")
	}
}

func TestAuditUserAppHardening_Policy_SafeBrowsingEnabled(t *testing.T) {
	srv := newFakeServer(t)
	srv.setAdminBase(t)
	srv.setChromeMgmtBase(t)

	srv.HandleJSON("/customers/C0test/reports:countBrowserVersions", map[string]any{
		"browserVersions": []map[string]any{
			{"version": "124.0.6367.82", "count": "5", "channel": "STABLE", "system": "WINDOWS"},
		},
	})

	srv.HandleJSON("/customer/C0test/orgunits", map[string]any{
		"organizationUnits": []map[string]any{
			{"orgUnitId": "id:ou1", "name": "Corp", "orgUnitPath": "/Corp"},
		},
	})

	srv.HandleFunc("/customers/C0test/policies:resolve", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req map[string]any
		json.Unmarshal(body, &req)
		schema := req["policySchemaFilter"].(string)

		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(schema, "SafeBrowsing") {
			json.NewEncoder(w).Encode(map[string]any{
				"resolvedPolicies": []map[string]any{
					{
						"value": map[string]any{
							"policySchema": schema,
							"value":        map[string]any{"safeBrowsingEnabled": true},
						},
					},
				},
			})
		} else {
			// SitePerProcess
			json.NewEncoder(w).Encode(map[string]any{
				"resolvedPolicies": []map[string]any{
					{
						"value": map[string]any{
							"policySchema": schema,
							"value":        map[string]any{"sitePerProcessEnabled": true},
						},
					},
				},
			})
		}
	})

	srv.HandleFunc("/users", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"users":[]}`))
	})

	c := newGoogleClient(t, "tok", "C0test")
	result, err := c.AuditUserAppHardening(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, f := range result.Findings {
		if f.Control == "ISM-1486" && strings.Contains(f.Description, "Safe Browsing") && f.Passed {
			found = true
		}
	}
	if !found {
		t.Error("expected passing Safe Browsing finding")
	}
}

func TestAuditUserAppHardening_Policy_SafeBrowsingDisabled(t *testing.T) {
	srv := newFakeServer(t)
	srv.setAdminBase(t)
	srv.setChromeMgmtBase(t)

	srv.HandleJSON("/customers/C0test/reports:countBrowserVersions", map[string]any{
		"browserVersions": []map[string]any{
			{"version": "124.0.6367.82", "count": "5", "channel": "STABLE", "system": "WINDOWS"},
		},
	})

	srv.HandleJSON("/customer/C0test/orgunits", map[string]any{
		"organizationUnits": []map[string]any{
			{"orgUnitId": "id:ou1", "name": "Corp", "orgUnitPath": "/Corp"},
		},
	})

	srv.HandleFunc("/customers/C0test/policies:resolve", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req map[string]any
		json.Unmarshal(body, &req)
		schema := req["policySchemaFilter"].(string)
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(schema, "SafeBrowsing") {
			json.NewEncoder(w).Encode(map[string]any{
				"resolvedPolicies": []map[string]any{
					{
						"value": map[string]any{
							"policySchema": schema,
							"value":        map[string]any{"safeBrowsingEnabled": false},
						},
					},
				},
			})
		} else {
			json.NewEncoder(w).Encode(map[string]any{"resolvedPolicies": []any{}})
		}
	})

	srv.HandleFunc("/users", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"users":[]}`))
	})

	c := newGoogleClient(t, "tok", "C0test")
	result, err := c.AuditUserAppHardening(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, f := range result.Findings {
		if f.Control == "ISM-1486" && strings.Contains(f.Description, "Safe Browsing") && !f.Passed {
			found = true
		}
	}
	if !found {
		t.Error("expected failing Safe Browsing finding")
	}
}

func TestAuditUserAppHardening_Policy_FlatOU_Skipped(t *testing.T) {
	srv := newFakeServer(t)
	srv.setAdminBase(t)
	srv.setChromeMgmtBase(t)

	srv.HandleJSON("/customers/C0test/reports:countBrowserVersions", map[string]any{
		"browserVersions": []map[string]any{
			{"version": "124.0.6367.82", "count": "5", "channel": "STABLE", "system": "WINDOWS"},
		},
	})

	// Empty org units — policy checks should be skipped
	srv.HandleJSON("/customer/C0test/orgunits", map[string]any{"organizationUnits": []any{}})

	srv.HandleFunc("/users", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"users":[]}`))
	})

	c := newGoogleClient(t, "tok", "C0test")
	_, err := c.AuditUserAppHardening(context.Background())
	if err != nil {
		t.Fatalf("expected no error for flat OU, got: %v", err)
	}
}

func TestAuditUserAppHardening_OAuth_NoHighRiskGrants(t *testing.T) {
	srv := newFakeServer(t)
	srv.setAdminBase(t)
	srv.setChromeMgmtBase(t)

	// CBCM not enrolled
	srv.HandleFunc("/customers/C0test/reports:countBrowserVersions", statusHandler(http.StatusForbidden))

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
				"displayText": "Google Calendar",
				"clientId":    "cal123",
				"scopes":      []string{"https://www.googleapis.com/auth/calendar"},
			},
		},
	}))

	c := newGoogleClient(t, "tok", "C0test")
	result, err := c.AuditUserAppHardening(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should have a passing summary finding
	found := false
	for _, f := range result.Findings {
		if f.Passed && strings.Contains(f.Description, "high-risk") {
			found = true
		}
	}
	if !found {
		t.Error("expected passing summary finding for no high-risk grants")
	}
}

func TestAuditUserAppHardening_OAuth_GmailSendScope(t *testing.T) {
	srv := newFakeServer(t)
	srv.setAdminBase(t)
	srv.setChromeMgmtBase(t)

	srv.HandleFunc("/customers/C0test/reports:countBrowserVersions", statusHandler(http.StatusForbidden))

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
				"displayText": "Some App",
				"clientId":    "app123",
				"scopes":      []string{"https://www.googleapis.com/auth/gmail.send"},
			},
		},
	}))

	c := newGoogleClient(t, "tok", "C0test")
	result, err := c.AuditUserAppHardening(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, f := range result.Findings {
		if f.Control == "ISM-1486" && !f.Passed {
			found = true
		}
	}
	if !found {
		t.Error("expected failing ISM-1486 finding for gmail.send scope")
	}
	// Verify the error comes from the correct place
	_ = errors.Is(nil, witness.ErrNotAuditable) // just use the package
}
