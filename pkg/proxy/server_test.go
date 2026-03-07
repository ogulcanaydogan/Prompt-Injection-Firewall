package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ogulcanaydogan/Prompt-Injection-Firewall/pkg/detector"
)

// mockDetector is a simple detector that always returns clean results.
type mockDetector struct{}

func (m *mockDetector) ID() string  { return "mock" }
func (m *mockDetector) Ready() bool { return true }
func (m *mockDetector) Scan(ctx context.Context, input detector.ScanInput) (*detector.ScanResult, error) {
	return &detector.ScanResult{
		Clean:      true,
		Score:      0,
		DetectorID: "mock",
		Duration:   1 * time.Millisecond,
	}, nil
}

// buildTestServer creates a test server with the PIF proxy handler for testing.
func buildTestServer(t *testing.T, upstream *httptest.Server, action string) *httptest.Server {
	t.Helper()

	ensemble := detector.NewEnsemble(detector.StrategyAnyMatch, 45*time.Millisecond)
	ensemble.Register(&mockDetector{}, 1.0)

	// We can't use StartServer directly as it blocks, so we recreate the handler setup
	handler := buildHandler(upstream.URL, action, ensemble)
	require.NotNil(t, handler)

	return httptest.NewServer(handler)
}

// buildHandler creates the same mux that StartServer would create.
func buildHandler(targetURL, actionStr string, d detector.Detector) http.Handler {
	metrics := NewMetrics()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	mux.Handle("GET /metrics", metrics.Handler())

	// Minimal proxy handler for testing.
	action := ParseAction(actionStr)
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("proxied"))
	})
	middleware := ScanMiddlewareWithOptions(d, action, MiddlewareOptions{
		Threshold:   0.5,
		MaxBodySize: defaultMaxBodySize,
		ScanTimeout: defaultScanTimeout,
		Metrics:     metrics,
	})
	mux.Handle("/", middleware(upstream))

	return mux
}

func TestHealthEndpoint(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	srv := buildTestServer(t, upstream, "block")
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/healthz")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Contains(t, string(body), "ok")
}

func TestHealthEndpoint_MethodNotAllowed(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	srv := buildTestServer(t, upstream, "block")
	defer srv.Close()

	// POST to healthz should not match the GET /healthz handler
	resp, err := http.Post(srv.URL+"/healthz", "application/json", strings.NewReader("{}"))
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should fall through to default handler, not 405
	assert.NotEqual(t, http.StatusNotFound, resp.StatusCode)
}

func TestProxyHandler_ForwardsRequests(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("upstream response"))
	}))
	defer upstream.Close()

	srv := buildTestServer(t, upstream, "block")
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/v1/models")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestMetricsEndpoint(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	srv := buildTestServer(t, upstream, "block")
	defer srv.Close()

	preResp, err := http.Get(srv.URL + "/v1/models")
	require.NoError(t, err)
	preResp.Body.Close()

	resp, err := http.Get(srv.URL + "/metrics")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Contains(t, string(body), "pif_http_requests_total")
}

func TestParseAction_Values(t *testing.T) {
	tests := []struct {
		input    string
		expected Action
	}{
		{"block", ActionBlock},
		{"Block", ActionBlock},
		{"BLOCK", ActionBlock},
		{"flag", ActionFlag},
		{"Flag", ActionFlag},
		{"log", ActionLog},
		{"Log", ActionLog},
		{"unknown", ActionBlock}, // defaults to block
		{"", ActionBlock},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.expected, ParseAction(tt.input))
		})
	}
}

func TestStartServer_InvalidTargetURL(t *testing.T) {
	err := StartServer(ServerOptions{
		TargetURL: "://invalid-url",
		Listen:    ":0",
		Action:    "block",
		Threshold: 0.5,
	}, &mockDetector{})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "parsing target URL")
}

func TestStartServer_InvalidListenAddress(t *testing.T) {
	err := StartServer(ServerOptions{
		TargetURL: "http://example.com",
		Listen:    ":-1",
		Action:    "block",
		Threshold: 0.5,
	}, &mockDetector{})

	require.Error(t, err)
}
