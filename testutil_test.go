package witness_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/e8evidence/witness"
)

// fakeServer wraps an httptest.Server with a configurable ServeMux.
type fakeServer struct {
	srv *httptest.Server
	mux *http.ServeMux
	// URL is the base URL of the fake server
	URL string
}

func newFakeServer(t *testing.T) *fakeServer {
	t.Helper()
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &fakeServer{srv: srv, mux: mux, URL: srv.URL}
}

func (f *fakeServer) Handle(pattern string, handler http.Handler) {
	f.mux.Handle(pattern, handler)
}

func (f *fakeServer) HandleFunc(pattern string, handler http.HandlerFunc) {
	f.mux.HandleFunc(pattern, handler)
}

func (f *fakeServer) HandleJSON(pattern string, v any) {
	f.mux.HandleFunc(pattern, jsonHandler(v))
}

func (f *fakeServer) setAdminBase(t *testing.T) {
	t.Helper()
	old := *witness.AdminSDKBaseVar
	*witness.AdminSDKBaseVar = f.srv.URL
	t.Cleanup(func() { *witness.AdminSDKBaseVar = old })
}

func (f *fakeServer) setChromeMgmtBase(t *testing.T) {
	t.Helper()
	old := *witness.ChromeMgmtBaseVar
	*witness.ChromeMgmtBaseVar = f.srv.URL
	t.Cleanup(func() { *witness.ChromeMgmtBaseVar = old })
}

func (f *fakeServer) setVaultBase(t *testing.T) {
	t.Helper()
	old := *witness.VaultBaseVar
	*witness.VaultBaseVar = f.srv.URL
	t.Cleanup(func() { *witness.VaultBaseVar = old })
}

func (f *fakeServer) setGraphBase(t *testing.T) {
	t.Helper()
	old := *witness.GraphBaseURLVar
	*witness.GraphBaseURLVar = f.srv.URL
	t.Cleanup(func() { *witness.GraphBaseURLVar = old })
}

func (f *fakeServer) setTokenURL(t *testing.T) {
	t.Helper()
	old := *witness.GoogleTokenURLVar
	*witness.GoogleTokenURLVar = f.srv.URL + "/token"
	t.Cleanup(func() { *witness.GoogleTokenURLVar = old })
}

// newGoogleClient creates a GoogleWorkspaceClient for testing.
func newGoogleClient(t *testing.T, token, customerID string) *witness.GoogleWorkspaceClient {
	t.Helper()
	return witness.NewGoogleWorkspaceClientForTest(http.DefaultClient, token, customerID)
}

// newMSClient creates an MSGraphClient for testing.
// It uses a custom transport that routes all requests through the fakeServer.
func newMSClient(t *testing.T, token, tenantID string) *witness.MSGraphClient {
	t.Helper()
	// We use http.DefaultClient (transport) but the URL override handles routing.
	return witness.NewMSGraphClientForTest(http.DefaultClient, token, tenantID)
}

// roundTripFunc is a function that implements http.RoundTripper.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

// newMSClientWithMux creates an MSGraphClient with a custom transport that
// routes requests to the given ServeMux. This bypasses URL parsing issues
// with spaces in query parameters (e.g. $filter in Graph API URLs).
// The transport strips the graphBaseURL path prefix so handlers are registered
// with paths like "/roleManagement/directory/roleAssignments".
func newMSClientWithMux(t *testing.T, token, tenantID string, mux *http.ServeMux) *witness.MSGraphClient {
	t.Helper()
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		rr := httptest.NewRecorder()
		// Strip the graphBaseURL path prefix so the mux sees "/roleManagement/..."
		// graphBaseURL might be "https://graph.microsoft.com/v1.0" or a test URL.
		graphBase := *witness.GraphBaseURLVar
		if parsed, err := url.Parse(graphBase); err == nil && parsed.Path != "" {
			rawPath := req.URL.Path
			if strings.HasPrefix(rawPath, parsed.Path) {
				req.URL.Path = rawPath[len(parsed.Path):]
				if req.URL.Path == "" {
					req.URL.Path = "/"
				}
			}
		}
		mux.ServeHTTP(rr, req)
		return rr.Result(), nil
	})
	hc := &http.Client{Transport: transport}
	return witness.NewMSGraphClientForTest(hc, token, tenantID)
}

// jsonHandler returns a handler that writes v as JSON with status 200.
func jsonHandler(v any) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(v); err != nil {
			http.Error(w, "encode error", http.StatusInternalServerError)
		}
	}
}

// statusHandler returns a handler that writes the given status code.
func statusHandler(code int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(code)
	}
}
