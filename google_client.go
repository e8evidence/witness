package witness

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Base URLs for Google APIs — package-level vars so tests can override them.
var (
	adminSDKBase   = "https://admin.googleapis.com/admin/directory/v1"
	chromeMgmtBase = "https://chromemanagement.googleapis.com/v1"
	vaultBase      = "https://vault.googleapis.com/v1"
	googleTokenURL = "https://oauth2.googleapis.com/token"
)

// GoogleWorkspaceClient audits a Google Workspace tenant via the Admin SDK
// and Chrome Management APIs.
type GoogleWorkspaceClient struct {
	httpClient *http.Client
	log        *slog.Logger
	token      string
	customerID string
}

// NewGoogleWorkspaceClient returns a ready-to-use client.
//
// If creds.AccessToken is non-empty it is used directly. Otherwise a
// standard refresh-token exchange is performed using the remaining fields.
func NewGoogleWorkspaceClient(ctx context.Context, creds GoogleCredentials, log *slog.Logger) (*GoogleWorkspaceClient, error) {
	token := creds.AccessToken
	if token == "" {
		var err error
		token, err = exchangeGoogleRefreshToken(ctx, creds)
		if err != nil {
			return nil, fmt.Errorf("GoogleWorkspaceClient: token exchange: %w", err)
		}
	}
	return &GoogleWorkspaceClient{
		httpClient: &http.Client{Timeout: 30 * time.Second},
		log:        log,
		token:      token,
		customerID: creds.CustomerID,
	}, nil
}

// --- Admin SDK response types ---------------------------------------------

type gsuiteUser struct {
	PrimaryEmail    string `json:"primaryEmail"`
	IsAdmin         bool   `json:"isAdmin"`
	IsEnrolledIn2Sv bool   `json:"isEnrolledIn2Sv"`
}

type gsuiteUserList struct {
	Users         []gsuiteUser `json:"users"`
	NextPageToken string       `json:"nextPageToken"`
}

// browserVersionSummary is one entry from the Chrome Management API
// countBrowserVersions report — one row per (version, channel, system) group.
type browserVersionSummary struct {
	Version string // e.g. "124.0.6367.82"
	Count   int    // number of managed browsers at this version+channel+system
	Channel string // "STABLE" | "BETA" | "DEV" | "CANARY"
	System  string // "SYSTEM_WIN" | "SYSTEM_MAC" | "SYSTEM_LINUX"
}

type chromeOSDevice struct {
	DeviceID       string `json:"deviceId"`
	Model          string `json:"model"`
	OsVersion      string `json:"osVersion"`
	LastSync       string `json:"lastSync"`
	Status         string `json:"status"`
	SupportEndDate string `json:"supportEndDate"` // AUE date: "YYYY-MM-DD" or empty
}

type chromeOSDeviceList struct {
	Chromeosdevices []chromeOSDevice `json:"chromeosdevices"`
	NextPageToken   string           `json:"nextPageToken"`
}

type vaultMatter struct {
	MatterID string `json:"matterId"`
	Name     string `json:"name"`
	State    string `json:"state"`
}

type vaultMatterList struct {
	Matters       []vaultMatter `json:"matters"`
	NextPageToken string        `json:"nextPageToken"`
}

// --- List helpers ---------------------------------------------------------

func (c *GoogleWorkspaceClient) listSuperAdmins(ctx context.Context) ([]gsuiteUser, error) {
	path := fmt.Sprintf("/users?customer=%s&query=isAdmin%%3Dtrue&maxResults=500&projection=basic", c.customerID)
	var result gsuiteUserList
	if err := c.adminGet(ctx, path, &result); err != nil {
		return nil, err
	}
	return result.Users, nil
}

// listAllUsers returns all users in the domain with pagination.
func (c *GoogleWorkspaceClient) listAllUsers(ctx context.Context) ([]gsuiteUser, error) {
	var all []gsuiteUser
	pageToken := ""
	for {
		path := fmt.Sprintf("/users?customer=%s&maxResults=500&projection=basic", c.customerID)
		if pageToken != "" {
			path += "&pageToken=" + url.QueryEscape(pageToken)
		}
		var result gsuiteUserList
		if err := c.adminGet(ctx, path, &result); err != nil {
			return nil, err
		}
		all = append(all, result.Users...)
		if result.NextPageToken == "" {
			break
		}
		pageToken = result.NextPageToken
	}
	return all, nil
}

// listChromeOSDevices returns all enrolled ChromeOS devices with pagination.
func (c *GoogleWorkspaceClient) listChromeOSDevices(ctx context.Context) ([]chromeOSDevice, error) {
	var all []chromeOSDevice
	pageToken := ""
	for {
		path := fmt.Sprintf("/customer/%s/devices/chromeos?maxResults=500&projection=BASIC", c.customerID)
		if pageToken != "" {
			path += "&pageToken=" + url.QueryEscape(pageToken)
		}
		var result chromeOSDeviceList
		if err := c.adminGet(ctx, path, &result); err != nil {
			return nil, err
		}
		all = append(all, result.Chromeosdevices...)
		if result.NextPageToken == "" {
			break
		}
		pageToken = result.NextPageToken
	}
	return all, nil
}

// listVaultMatters returns open Vault matters.
// licensed is false when the API responds with 403 (Vault not licensed for tenant).
func (c *GoogleWorkspaceClient) listVaultMatters(ctx context.Context) ([]vaultMatter, bool, error) {
	path := vaultBase + "/matters?pageSize=100&state=OPEN"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, false, fmt.Errorf("vault GET matters: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden {
		return nil, false, nil // Vault not licensed
	}

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("vault GET matters: HTTP %d: %s", resp.StatusCode, body)
	}

	var result vaultMatterList
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, false, fmt.Errorf("vault GET matters: decode: %w", err)
	}
	return result.Matters, true, nil
}

// listManagedBrowserVersions calls the Chrome Management Reports API
// countBrowserVersions endpoint and returns aggregated browser version data.
//
// Returns ErrNotAuditable when no managed browsers are found (CBCM not set up)
// or when the API is unavailable (HTTP 403/404).
func (c *GoogleWorkspaceClient) listManagedBrowserVersions(ctx context.Context) ([]browserVersionSummary, error) {
	var all []browserVersionSummary
	pageToken := ""
	for {
		path := fmt.Sprintf("%s/customers/%s/reports:countBrowserVersions", chromeMgmtBase, c.customerID)
		if pageToken != "" {
			path += "?pageToken=" + url.QueryEscape(pageToken)
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, path, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+c.token)

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("countBrowserVersions: %w", err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusForbidden {
			return nil, fmt.Errorf(
				"Chrome Management API unavailable (HTTP %d) — CBCM may not be enrolled: %w",
				resp.StatusCode, ErrNotAuditable,
			)
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("countBrowserVersions: HTTP %d: %s", resp.StatusCode, body)
		}

		var result struct {
			BrowserVersions []struct {
				Version string `json:"version"`
				Count   string `json:"count"` // API returns int64 as string
				Channel string `json:"channel"`
				System  string `json:"system"`
			} `json:"browserVersions"`
			NextPageToken string `json:"nextPageToken"`
		}
		if err := json.Unmarshal(body, &result); err != nil {
			return nil, fmt.Errorf("countBrowserVersions: decode: %w", err)
		}

		for _, entry := range result.BrowserVersions {
			count, _ := strconv.Atoi(entry.Count)
			all = append(all, browserVersionSummary{
				Version: entry.Version,
				Count:   count,
				Channel: entry.Channel,
				System:  entry.System,
			})
		}

		if result.NextPageToken == "" {
			break
		}
		pageToken = result.NextPageToken
	}
	return all, nil
}

// --- Core HTTP helper -----------------------------------------------------

// adminGet performs an authenticated GET against the Admin SDK and decodes
// JSON into dest.
func (c *GoogleWorkspaceClient) adminGet(ctx context.Context, path string, dest any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, adminSDKBase+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("admin GET %s: %w", path, err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("admin GET %s: HTTP %d: %s", path, resp.StatusCode, body)
	}
	return json.Unmarshal(body, dest)
}

// --- Token exchange -------------------------------------------------------

// exchangeGoogleRefreshToken is a package function (not a method) so it has no
// access to the client's httpClient; it creates a short-lived client for this
// single request.
func exchangeGoogleRefreshToken(ctx context.Context, creds GoogleCredentials) (string, error) {
	data := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {creds.ClientID},
		"client_secret": {creds.ClientSecret},
		"refresh_token": {creds.RefreshToken},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, googleTokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("google token request: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("google token exchange HTTP %d: %s", resp.StatusCode, body)
	}

	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return "", fmt.Errorf("google token parse: %w", err)
	}
	return tok.AccessToken, nil
}

// --- Shared scan helpers --------------------------------------------------

// collectUsersToScan merges admins and regular users, deduplicating by email.
func collectUsersToScan(admins, regular []gsuiteUser) []gsuiteUser {
	seen := make(map[string]bool, len(admins)+len(regular))
	out := make([]gsuiteUser, 0, len(admins)+len(regular))
	for _, u := range append(admins, regular...) { //nolint:gocritic // single allocation, not aliased
		if !seen[u.PrimaryEmail] {
			seen[u.PrimaryEmail] = true
			out = append(out, u)
		}
	}
	return out
}
