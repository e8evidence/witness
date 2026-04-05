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

func TestAuditAppControl_CBCM_NotEnrolled_ErrNotAuditable(t *testing.T) {
	srv := newFakeServer(t)
	srv.setAdminBase(t)
	srv.setChromeMgmtBase(t)

	srv.HandleFunc("/customers/C0test/reports:countBrowserVersions", statusHandler(http.StatusForbidden))

	c := newGoogleClient(t, "tok", "C0test")
	_, err := c.AuditAppControl(context.Background())
	if !errors.Is(err, witness.ErrNotAuditable) {
		t.Errorf("expected ErrNotAuditable, got: %v", err)
	}
}

func TestAuditAppControl_CBCM_BrowsersPresent(t *testing.T) {
	srv := newFakeServer(t)
	srv.setAdminBase(t)
	srv.setChromeMgmtBase(t)

	srv.HandleJSON("/customers/C0test/reports:countBrowserVersions", map[string]any{
		"browserVersions": []map[string]any{
			{"version": "124.0.6367.82", "count": "5", "channel": "STABLE", "system": "WINDOWS"},
		},
	})

	// Flat OU — policy checks skipped
	srv.HandleJSON("/customer/C0test/orgunits", map[string]any{"organizationUnits": []any{}})

	// installed apps
	srv.HandleFunc("/customers/C0test/reports:countInstalledApps", func(w http.ResponseWriter, r *http.Request) {
		jsonHandler(map[string]any{"installedApps": []any{}})(w, r)
	})

	c := newGoogleClient(t, "tok", "C0test")
	result, err := c.AuditAppControl(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, f := range result.Findings {
		if f.Control == "ISM-0140" && f.Passed {
			found = true
		}
	}
	if !found {
		t.Error("expected passing ISM-0140 finding when browsers enrolled")
	}
}

func TestAuditAppControl_CBCM_NoBrowsersRegistered(t *testing.T) {
	srv := newFakeServer(t)
	srv.setAdminBase(t)
	srv.setChromeMgmtBase(t)

	// CBCM enrolled but count=0
	srv.HandleJSON("/customers/C0test/reports:countBrowserVersions", map[string]any{
		"browserVersions": []any{},
	})

	// Even with empty list, CBCM is "enrolled" (API returned 200)
	// The AuditAppControl code treats this as enrolled but no browsers
	// Actually looking at code: if 200 but empty -> totalBrowsers=0 -> failing ISM-0140
	// The ErrNotAuditable wraps happen only on non-200 codes

	// Wait — the code for AuditAppControl wraps ErrNotAuditable from listManagedBrowserVersions.
	// listManagedBrowserVersions returns ErrNotAuditable for 403/404 but NOT for empty list.
	// So an empty list (200) means CBCM is enrolled but no browsers registered.
	// AuditChrome separately returns ErrNotAuditable for empty list, but AuditAppControl doesn't.

	srv.HandleJSON("/customer/C0test/orgunits", map[string]any{"organizationUnits": []any{}})
	srv.HandleFunc("/customers/C0test/reports:countInstalledApps", func(w http.ResponseWriter, r *http.Request) {
		jsonHandler(map[string]any{"installedApps": []any{}})(w, r)
	})

	c := newGoogleClient(t, "tok", "C0test")
	result, err := c.AuditAppControl(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, f := range result.Findings {
		if f.Control == "ISM-0140" && !f.Passed {
			found = true
		}
	}
	if !found {
		t.Error("expected failing ISM-0140 finding when enrolled but no browsers registered")
	}
}

func TestAuditAppControl_Blocklist_WildcardSet(t *testing.T) {
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
		if strings.Contains(schema, "Blocklist") {
			json.NewEncoder(w).Encode(map[string]any{
				"resolvedPolicies": []map[string]any{
					{
						"value": map[string]any{
							"policySchema": schema,
							"value":        map[string]any{"extensionInstallBlocklist": []any{"*"}},
						},
					},
				},
			})
		} else {
			// Allowlist
			json.NewEncoder(w).Encode(map[string]any{
				"resolvedPolicies": []map[string]any{
					{
						"value": map[string]any{
							"policySchema": schema,
							"value":        map[string]any{"extensionInstallAllowlist": []any{"ext1"}},
						},
					},
				},
			})
		}
	})

	srv.HandleFunc("/customers/C0test/reports:countInstalledApps", func(w http.ResponseWriter, r *http.Request) {
		jsonHandler(map[string]any{"installedApps": []any{}})(w, r)
	})

	c := newGoogleClient(t, "tok", "C0test")
	result, err := c.AuditAppControl(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, f := range result.Findings {
		if f.Control == "ISM-1490" && f.Passed && strings.Contains(f.Description, "*") {
			found = true
		}
	}
	if !found {
		t.Error("expected passing ISM-1490 finding for wildcard blocklist")
	}
}

func TestAuditAppControl_Blocklist_NotWildcard(t *testing.T) {
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
		if strings.Contains(schema, "Blocklist") {
			json.NewEncoder(w).Encode(map[string]any{
				"resolvedPolicies": []map[string]any{
					{
						"value": map[string]any{
							"policySchema": schema,
							"value":        map[string]any{"extensionInstallBlocklist": []any{"specific-id"}},
						},
					},
				},
			})
		} else {
			json.NewEncoder(w).Encode(map[string]any{"resolvedPolicies": []any{}})
		}
	})

	srv.HandleFunc("/customers/C0test/reports:countInstalledApps", func(w http.ResponseWriter, r *http.Request) {
		jsonHandler(map[string]any{"installedApps": []any{}})(w, r)
	})

	c := newGoogleClient(t, "tok", "C0test")
	result, err := c.AuditAppControl(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, f := range result.Findings {
		if f.Control == "ISM-1490" && !f.Passed {
			found = true
		}
	}
	if !found {
		t.Error("expected failing ISM-1490 finding when blocklist doesn't contain wildcard")
	}
}

func TestAuditAppControl_Allowlist_Configured(t *testing.T) {
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
		if strings.Contains(schema, "Blocklist") {
			json.NewEncoder(w).Encode(map[string]any{
				"resolvedPolicies": []map[string]any{
					{
						"value": map[string]any{
							"policySchema": schema,
							"value":        map[string]any{"extensionInstallBlocklist": []any{"*"}},
						},
					},
				},
			})
		} else {
			// Allowlist has 2 extensions
			json.NewEncoder(w).Encode(map[string]any{
				"resolvedPolicies": []map[string]any{
					{
						"value": map[string]any{
							"policySchema": schema,
							"value":        map[string]any{"extensionInstallAllowlist": []any{"ext1", "ext2"}},
						},
					},
				},
			})
		}
	})

	srv.HandleFunc("/customers/C0test/reports:countInstalledApps", func(w http.ResponseWriter, r *http.Request) {
		jsonHandler(map[string]any{"installedApps": []any{}})(w, r)
	})

	c := newGoogleClient(t, "tok", "C0test")
	result, err := c.AuditAppControl(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, f := range result.Findings {
		if f.Control == "ISM-1490" && f.Passed && strings.Contains(f.Description, "2") {
			found = true
		}
	}
	if !found {
		t.Error("expected passing ISM-1490 allowlist finding with count=2")
	}
}

func TestAuditAppControl_Allowlist_Empty(t *testing.T) {
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
		if strings.Contains(schema, "Blocklist") {
			json.NewEncoder(w).Encode(map[string]any{
				"resolvedPolicies": []map[string]any{
					{
						"value": map[string]any{
							"policySchema": schema,
							"value":        map[string]any{"extensionInstallBlocklist": []any{"*"}},
						},
					},
				},
			})
		} else {
			// Empty allowlist (not explicitly set)
			json.NewEncoder(w).Encode(map[string]any{"resolvedPolicies": []any{}})
		}
	})

	srv.HandleFunc("/customers/C0test/reports:countInstalledApps", func(w http.ResponseWriter, r *http.Request) {
		jsonHandler(map[string]any{"installedApps": []any{}})(w, r)
	})

	c := newGoogleClient(t, "tok", "C0test")
	result, err := c.AuditAppControl(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, f := range result.Findings {
		if f.Control == "ISM-1490" && !f.Passed && strings.Contains(f.Description, "allowlist") {
			found = true
		}
	}
	if !found {
		t.Error("expected failing allowlist ISM-1490 finding when no allowlist configured")
	}
}

func TestAuditAppControl_FlatOU_PolicySkipped(t *testing.T) {
	srv := newFakeServer(t)
	srv.setAdminBase(t)
	srv.setChromeMgmtBase(t)

	srv.HandleJSON("/customers/C0test/reports:countBrowserVersions", map[string]any{
		"browserVersions": []map[string]any{
			{"version": "124.0.6367.82", "count": "5", "channel": "STABLE", "system": "WINDOWS"},
		},
	})

	// Flat OU — no child OUs
	srv.HandleJSON("/customer/C0test/orgunits", map[string]any{"organizationUnits": []any{}})

	srv.HandleFunc("/customers/C0test/reports:countInstalledApps", func(w http.ResponseWriter, r *http.Request) {
		jsonHandler(map[string]any{"installedApps": []any{}})(w, r)
	})

	c := newGoogleClient(t, "tok", "C0test")
	result, err := c.AuditAppControl(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Only CBCM finding — no ISM-1490 findings
	for _, f := range result.Findings {
		if f.Control == "ISM-1490" {
			t.Errorf("expected no ISM-1490 findings for flat OU, got: %+v", f)
		}
	}
}

func TestAuditAppControl_InstalledApps_Counted(t *testing.T) {
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
		if strings.Contains(schema, "Blocklist") {
			json.NewEncoder(w).Encode(map[string]any{
				"resolvedPolicies": []map[string]any{
					{
						"value": map[string]any{
							"policySchema": schema,
							"value":        map[string]any{"extensionInstallBlocklist": []any{"*"}},
						},
					},
				},
			})
		} else {
			json.NewEncoder(w).Encode(map[string]any{"resolvedPolicies": []any{}})
		}
	})

	srv.HandleFunc("/customers/C0test/reports:countInstalledApps", func(w http.ResponseWriter, r *http.Request) {
		jsonHandler(map[string]any{
			"installedApps": []map[string]any{
				{"appId": "ext1", "appType": "EXTENSION", "appName": "uBlock Origin", "browserDeviceCount": 5},
				{"appId": "ext2", "appType": "EXTENSION", "appName": "JSON Viewer", "browserDeviceCount": 3},
			},
		})(w, r)
	})

	c := newGoogleClient(t, "tok", "C0test")
	result, err := c.AuditAppControl(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Evidence should contain the installed app count
	found := false
	for _, f := range result.Findings {
		if strings.Contains(f.Evidence, "totalDistinctExtensions") {
			found = true
		}
	}
	if !found {
		t.Error("expected evidence containing totalDistinctExtensions")
	}
}
