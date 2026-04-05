package witness_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/e8evidence/witness"
)

func TestAuditPatchOS_ChromeOS_AllWithin14d(t *testing.T) {
	srv := newFakeServer(t)
	srv.setAdminBase(t)
	srv.setChromeMgmtBase(t)

	lastSync := time.Now().UTC().Add(-5 * 24 * time.Hour).Format(time.RFC3339Nano)
	supportEnd := time.Now().AddDate(1, 0, 0).Format("2006-01-02")

	srv.HandleFunc("/customer/C0test/devices/chromeos", jsonHandler(map[string]any{
		"chromeosdevices": []map[string]any{
			{
				"deviceId":       "dev1",
				"model":          "Chromebook",
				"osVersion":      "124.0.6367.82",
				"lastSync":       lastSync,
				"status":         "ACTIVE",
				"supportEndDate": supportEnd,
			},
		},
	}))
	// EV telemetry returns 404 (not available)
	srv.HandleFunc("/customers/C0test/telemetry/devices", statusHandler(http.StatusNotFound))

	c := newGoogleClient(t, "tok", "C0test")
	result, err := c.AuditPatchOS(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// 3 findings per device
	if len(result.Findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(result.Findings))
	}
	for _, f := range result.Findings {
		if !f.Passed {
			t.Errorf("expected all findings to pass, got: %+v", f)
		}
	}
	if result.Level != witness.ML3 {
		t.Errorf("expected ML3, got %s", result.Level)
	}
}

func TestAuditPatchOS_ChromeOS_StaleML2(t *testing.T) {
	srv := newFakeServer(t)
	srv.setAdminBase(t)
	srv.setChromeMgmtBase(t)

	lastSync := time.Now().UTC().Add(-20 * 24 * time.Hour).Format(time.RFC3339Nano)
	supportEnd := time.Now().AddDate(1, 0, 0).Format("2006-01-02")

	srv.HandleFunc("/customer/C0test/devices/chromeos", jsonHandler(map[string]any{
		"chromeosdevices": []map[string]any{
			{
				"deviceId":       "dev1",
				"model":          "Chromebook",
				"osVersion":      "124.0.6367.82",
				"lastSync":       lastSync,
				"status":         "ACTIVE",
				"supportEndDate": supportEnd,
			},
		},
	}))
	srv.HandleFunc("/customers/C0test/telemetry/devices", statusHandler(http.StatusNotFound))

	c := newGoogleClient(t, "tok", "C0test")
	result, err := c.AuditPatchOS(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// ISM-1877 pass, 30d pass, 14d fail => exactly 1 failing finding
	pass, fail := 0, 0
	for _, f := range result.Findings {
		if f.Passed {
			pass++
		} else {
			fail++
		}
	}
	if pass != 2 || fail != 1 {
		t.Errorf("expected 2 pass, 1 fail for stale 20d, got pass=%d fail=%d", pass, fail)
	}
	// Verify the scorer produces ML2
	scorer := witness.NewScorer(discardLogger())
	score := scorer.Score("t", "t", []witness.StrategyResult{result}, witness.ML0)
	if score.Strategies[0].Level != witness.ML2 {
		t.Errorf("expected ML2, got %s", score.Strategies[0].Level)
	}
}

func TestAuditPatchOS_ChromeOS_StaleML1(t *testing.T) {
	srv := newFakeServer(t)
	srv.setAdminBase(t)
	srv.setChromeMgmtBase(t)

	lastSync := time.Now().UTC().Add(-35 * 24 * time.Hour).Format(time.RFC3339Nano)
	supportEnd := time.Now().AddDate(1, 0, 0).Format("2006-01-02")

	srv.HandleFunc("/customer/C0test/devices/chromeos", jsonHandler(map[string]any{
		"chromeosdevices": []map[string]any{
			{
				"deviceId":       "dev1",
				"model":          "Chromebook",
				"osVersion":      "124.0.6367.82",
				"lastSync":       lastSync,
				"status":         "ACTIVE",
				"supportEndDate": supportEnd,
			},
		},
	}))
	srv.HandleFunc("/customers/C0test/telemetry/devices", statusHandler(http.StatusNotFound))

	c := newGoogleClient(t, "tok", "C0test")
	result, err := c.AuditPatchOS(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// ISM-1877 pass, 30d fail, 14d fail => 2 failing findings
	pass, fail := 0, 0
	for _, f := range result.Findings {
		if f.Passed {
			pass++
		} else {
			fail++
		}
	}
	if pass != 1 || fail != 2 {
		t.Errorf("expected 1 pass, 2 fail for stale 35d, got pass=%d fail=%d", pass, fail)
	}
	// Verify the scorer produces ML1
	scorer := witness.NewScorer(discardLogger())
	score := scorer.Score("t", "t", []witness.StrategyResult{result}, witness.ML0)
	if score.Strategies[0].Level != witness.ML1 {
		t.Errorf("expected ML1, got %s", score.Strategies[0].Level)
	}
}

func TestAuditPatchOS_ChromeOS_AUEExpired(t *testing.T) {
	srv := newFakeServer(t)
	srv.setAdminBase(t)
	srv.setChromeMgmtBase(t)

	lastSync := time.Now().UTC().Add(-5 * 24 * time.Hour).Format(time.RFC3339Nano)
	yesterday := time.Now().AddDate(0, 0, -1).Format("2006-01-02")

	srv.HandleFunc("/customer/C0test/devices/chromeos", jsonHandler(map[string]any{
		"chromeosdevices": []map[string]any{
			{
				"deviceId":       "dev1",
				"model":          "Chromebook",
				"osVersion":      "109.0.5414.125",
				"lastSync":       lastSync,
				"status":         "ACTIVE",
				"supportEndDate": yesterday,
			},
		},
	}))
	srv.HandleFunc("/customers/C0test/telemetry/devices", statusHandler(http.StatusNotFound))

	c := newGoogleClient(t, "tok", "C0test")
	result, err := c.AuditPatchOS(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// ISM-1877 should fail
	aueFound := false
	for _, f := range result.Findings {
		if f.Control == "ISM-1877" {
			aueFound = true
			if f.Passed {
				t.Error("expected ISM-1877 finding to fail for expired AUE")
			}
		}
	}
	if !aueFound {
		t.Error("expected ISM-1877 finding")
	}
}

func TestAuditPatchOS_ChromeOS_EmptyAUE(t *testing.T) {
	srv := newFakeServer(t)
	srv.setAdminBase(t)
	srv.setChromeMgmtBase(t)

	lastSync := time.Now().UTC().Add(-5 * 24 * time.Hour).Format(time.RFC3339Nano)

	srv.HandleFunc("/customer/C0test/devices/chromeos", jsonHandler(map[string]any{
		"chromeosdevices": []map[string]any{
			{
				"deviceId":       "dev1",
				"model":          "Chromebook",
				"osVersion":      "124.0.6367.82",
				"lastSync":       lastSync,
				"status":         "ACTIVE",
				"supportEndDate": "",
			},
		},
	}))
	srv.HandleFunc("/customers/C0test/telemetry/devices", statusHandler(http.StatusNotFound))

	c := newGoogleClient(t, "tok", "C0test")
	result, err := c.AuditPatchOS(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// ISM-1877 should pass (empty AUE treated as supported)
	for _, f := range result.Findings {
		if f.Control == "ISM-1877" && !f.Passed {
			t.Error("expected ISM-1877 finding to pass for empty AUE")
		}
	}
}

func TestAuditPatchOS_NoChromeOS_NoEV(t *testing.T) {
	srv := newFakeServer(t)
	srv.setAdminBase(t)
	srv.setChromeMgmtBase(t)

	srv.HandleJSON("/customer/C0test/devices/chromeos", map[string]any{"chromeosdevices": []any{}})
	srv.HandleFunc("/customers/C0test/telemetry/devices", statusHandler(http.StatusNotFound))

	c := newGoogleClient(t, "tok", "C0test")
	_, err := c.AuditPatchOS(context.Background())
	if !errors.Is(err, witness.ErrNotAuditable) {
		t.Errorf("expected ErrNotAuditable, got: %v", err)
	}
}

func TestAuditPatchOS_NoChromeOS_EVAvailable(t *testing.T) {
	srv := newFakeServer(t)
	srv.setAdminBase(t)
	srv.setChromeMgmtBase(t)

	lastReg := time.Now().UTC().Add(-3 * 24 * time.Hour).Format(time.RFC3339)

	srv.HandleJSON("/customer/C0test/devices/chromeos", map[string]any{"chromeosdevices": []any{}})
	srv.HandleJSON("/customers/C0test/telemetry/devices", map[string]any{
		"devices": []map[string]any{
			{
				"deviceId": "ev-dev1",
				"osInfo": map[string]any{
					"osVersion":      "10.0.19044",
					"osPlatformType": "WINDOWS",
				},
				"deviceInfo": map[string]any{
					"lastRegistrationTime": lastReg,
				},
			},
		},
	})

	c := newGoogleClient(t, "tok", "C0test")
	result, err := c.AuditPatchOS(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) == 0 {
		t.Error("expected findings from EV devices")
	}
}

func TestAuditPatchOS_EV_ChromeOS_Platform_Skipped(t *testing.T) {
	srv := newFakeServer(t)
	srv.setAdminBase(t)
	srv.setChromeMgmtBase(t)

	lastReg := time.Now().UTC().Add(-3 * 24 * time.Hour).Format(time.RFC3339)

	srv.HandleJSON("/customer/C0test/devices/chromeos", map[string]any{"chromeosdevices": []any{}})
	srv.HandleJSON("/customers/C0test/telemetry/devices", map[string]any{
		"devices": []map[string]any{
			{
				"deviceId": "ev-cros",
				"osInfo": map[string]any{
					"osVersion":      "124.0.0",
					"osPlatformType": "CHROME_OS",
				},
				"deviceInfo": map[string]any{
					"lastRegistrationTime": lastReg,
				},
			},
		},
	})

	c := newGoogleClient(t, "tok", "C0test")
	_, err := c.AuditPatchOS(context.Background())
	if !errors.Is(err, witness.ErrNotAuditable) {
		t.Errorf("expected ErrNotAuditable when only CHROME_OS devices in EV, got: %v", err)
	}
}

func TestAuditPatchOS_ChromeOS_Pagination(t *testing.T) {
	srv := newFakeServer(t)
	srv.setAdminBase(t)
	srv.setChromeMgmtBase(t)

	lastSync := time.Now().UTC().Add(-5 * 24 * time.Hour).Format(time.RFC3339Nano)
	supportEnd := time.Now().AddDate(1, 0, 0).Format("2006-01-02")

	srv.HandleFunc("/customer/C0test/devices/chromeos", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		pageToken := r.URL.Query().Get("pageToken")
		device := func(id string) map[string]any {
			return map[string]any{
				"deviceId":       id,
				"model":          "Chromebook",
				"osVersion":      "124.0.6367.82",
				"lastSync":       lastSync,
				"status":         "ACTIVE",
				"supportEndDate": supportEnd,
			}
		}
		if pageToken == "" {
			resp := map[string]any{
				"chromeosdevices": []map[string]any{device("dev1")},
				"nextPageToken":   "page2",
			}
			_ = fmt.Sprintf("") // keep import
			jsonHandler(resp)(w, r)
		} else if pageToken == "page2" {
			jsonHandler(map[string]any{
				"chromeosdevices": []map[string]any{device("dev2")},
			})(w, r)
		}
	})
	srv.HandleFunc("/customers/C0test/telemetry/devices", statusHandler(http.StatusNotFound))

	c := newGoogleClient(t, "tok", "C0test")
	result, err := c.AuditPatchOS(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// 2 devices * 3 findings = 6
	if len(result.Findings) != 6 {
		t.Errorf("expected 6 findings from 2 pages, got %d", len(result.Findings))
	}
}

func TestAuditPatchOS_ChromeOS_HardError(t *testing.T) {
	srv := newFakeServer(t)
	srv.setAdminBase(t)
	srv.setChromeMgmtBase(t)

	srv.HandleFunc("/customer/C0test/devices/chromeos", statusHandler(http.StatusInternalServerError))
	srv.HandleFunc("/customers/C0test/telemetry/devices", statusHandler(http.StatusNotFound))

	c := newGoogleClient(t, "tok", "C0test")
	_, err := c.AuditPatchOS(context.Background())
	if err == nil {
		t.Fatal("expected error from 500, got nil")
	}
	if errors.Is(err, witness.ErrNotAuditable) {
		t.Error("expected hard error, not ErrNotAuditable")
	}
}
