package witness_test

import (
	"context"
	"net/http"
	"testing"
)

func TestAuditMacroSettings_NoChromeOSDevices(t *testing.T) {
	srv := newFakeServer(t)
	srv.setAdminBase(t)
	srv.setChromeMgmtBase(t)

	srv.HandleJSON("/customer/C0test/devices/chromeos", map[string]any{
		"chromeosdevices": []any{},
	})

	c := newGoogleClient(t, "tok", "C0test")
	result, err := c.AuditMacroSettings(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	if !result.Findings[0].Passed {
		t.Error("expected passing finding when no devices")
	}
	if result.Findings[0].Control != "ISM-1671" {
		t.Errorf("expected control ISM-1671, got %s", result.Findings[0].Control)
	}
}

func TestAuditMacroSettings_DevicesNoOffice(t *testing.T) {
	srv := newFakeServer(t)
	srv.setAdminBase(t)
	srv.setChromeMgmtBase(t)

	srv.HandleFunc("/customer/C0test/devices/chromeos", func(w http.ResponseWriter, r *http.Request) {
		// Return a device with no Office apps regardless of projection
		jsonHandler(map[string]any{
			"chromeosdevices": []map[string]any{
				{
					"deviceId": "dev1",
					"model":    "Pixelbook",
					"applications": []map[string]any{
						{"displayName": "Google Drive", "appType": "WEB_APP"},
					},
				},
			},
		})(w, r)
	})

	c := newGoogleClient(t, "tok", "C0test")
	result, err := c.AuditMacroSettings(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	if !result.Findings[0].Passed {
		t.Error("expected passing finding when no Office apps detected")
	}
}

func TestAuditMacroSettings_OfficeAndroidAppFound(t *testing.T) {
	srv := newFakeServer(t)
	srv.setAdminBase(t)
	srv.setChromeMgmtBase(t)

	srv.HandleFunc("/customer/C0test/devices/chromeos", func(w http.ResponseWriter, r *http.Request) {
		jsonHandler(map[string]any{
			"chromeosdevices": []map[string]any{
				{
					"deviceId": "dev1",
					"model":    "Pixelbook",
					"applications": []map[string]any{
						{"displayName": "Microsoft Word", "appType": "ANDROID_APP"},
					},
				},
			},
		})(w, r)
	})

	c := newGoogleClient(t, "tok", "C0test")
	result, err := c.AuditMacroSettings(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) == 0 {
		t.Fatal("expected at least 1 finding")
	}
	if result.Findings[0].Passed {
		t.Error("expected failing finding for Office app")
	}
	if result.Findings[0].Control != "ISM-1671" {
		t.Errorf("expected control ISM-1671, got %s", result.Findings[0].Control)
	}
}

func TestAuditMacroSettings_Microsoft365WebApp(t *testing.T) {
	srv := newFakeServer(t)
	srv.setAdminBase(t)
	srv.setChromeMgmtBase(t)

	srv.HandleFunc("/customer/C0test/devices/chromeos", func(w http.ResponseWriter, r *http.Request) {
		jsonHandler(map[string]any{
			"chromeosdevices": []map[string]any{
				{
					"deviceId": "dev1",
					"model":    "Chromebook",
					"applications": []map[string]any{
						{"displayName": "Microsoft 365", "appType": "WEB_APP"},
					},
				},
			},
		})(w, r)
	})

	c := newGoogleClient(t, "tok", "C0test")
	result, err := c.AuditMacroSettings(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) == 0 || result.Findings[0].Passed {
		t.Error("expected failing finding for Microsoft 365 web app")
	}
}

func TestAuditMacroSettings_OneDevicePerFinding(t *testing.T) {
	srv := newFakeServer(t)
	srv.setAdminBase(t)
	srv.setChromeMgmtBase(t)

	srv.HandleFunc("/customer/C0test/devices/chromeos", func(w http.ResponseWriter, r *http.Request) {
		// One device with two Office apps — should only produce 1 finding
		jsonHandler(map[string]any{
			"chromeosdevices": []map[string]any{
				{
					"deviceId": "dev1",
					"model":    "Chromebook",
					"applications": []map[string]any{
						{"displayName": "Microsoft Word", "appType": "ANDROID_APP"},
						{"displayName": "Microsoft Excel", "appType": "ANDROID_APP"},
					},
				},
			},
		})(w, r)
	})

	c := newGoogleClient(t, "tok", "C0test")
	result, err := c.AuditMacroSettings(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Errorf("expected 1 finding per device (break after first match), got %d", len(result.Findings))
	}
}

func TestAuditMacroSettings_APIError(t *testing.T) {
	srv := newFakeServer(t)
	srv.setAdminBase(t)
	srv.setChromeMgmtBase(t)

	srv.HandleFunc("/customer/C0test/devices/chromeos", statusHandler(http.StatusInternalServerError))

	c := newGoogleClient(t, "tok", "C0test")
	_, err := c.AuditMacroSettings(context.Background())
	if err == nil {
		t.Fatal("expected error from 500, got nil")
	}
}
