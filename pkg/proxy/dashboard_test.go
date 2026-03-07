package proxy

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ogulcanaydogan/Prompt-Injection-Firewall/pkg/detector"
)

func buildDashboardTestServer(t *testing.T, dashboard DashboardOptions) *httptest.Server {
	t.Helper()

	ensemble := detector.NewEnsemble(detector.StrategyAnyMatch, 45*time.Millisecond)
	ensemble.Register(&mockDetector{}, 1.0)

	metrics := NewMetrics()
	opts := ServerOptions{
		TargetURL: "http://upstream.local",
		Listen:    ":0",
		Action:    "block",
		Threshold: 0.5,
		Metrics:   metrics,
		Dashboard: dashboard,
		RuleInventory: []RuleSetInfo{
			{Name: "owasp", Version: "1.0.0", RuleCount: 24},
			{Name: "jailbreak", Version: "1.0.0", RuleCount: 87},
		},
		RateLimit: RateLimitOptions{
			Enabled:           true,
			RequestsPerMinute: 120,
			Burst:             30,
			KeyHeader:         "X-Forwarded-For",
		},
		AdaptiveThreshold: AdaptiveThresholdOptions{
			Enabled:      true,
			MinThreshold: 0.25,
			EWMAAlpha:    0.2,
		},
	}

	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("proxied"))
	})

	middleware := ScanMiddlewareWithOptions(ensemble, ParseAction(opts.Action), MiddlewareOptions{
		Threshold:   opts.Threshold,
		MaxBodySize: defaultMaxBodySize,
		ScanTimeout: defaultScanTimeout,
		Metrics:     metrics,
	})

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	mux.Handle("GET /metrics", metrics.Handler())
	if dashboard.Enabled {
		registerDashboardRoutes(mux, opts)
	} else {
		registerDashboardNotFoundRoutes(mux, dashboard.Path, dashboard.APIPrefix)
	}
	mux.Handle("/", middleware(upstream))

	return httptest.NewServer(mux)
}

func TestDashboardDisabled_ReturnsNotFound(t *testing.T) {
	srv := buildDashboardTestServer(t, DashboardOptions{
		Enabled:   false,
		Path:      "/dashboard",
		APIPrefix: "/api/dashboard",
	})
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/dashboard")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)

	resp2, err := http.Get(srv.URL + "/api/dashboard/summary")
	require.NoError(t, err)
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp2.StatusCode)
}

func TestDashboardEnabled_NoAuth(t *testing.T) {
	srv := buildDashboardTestServer(t, DashboardOptions{
		Enabled:        true,
		Path:           "/dashboard",
		APIPrefix:      "/api/dashboard",
		RefreshSeconds: 5,
		Auth: DashboardAuthOptions{
			Enabled: false,
		},
	})
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/dashboard")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Contains(t, string(body), "Prompt Injection Firewall")

	jsResp, err := http.Get(srv.URL + "/dashboard/app.js")
	require.NoError(t, err)
	defer jsResp.Body.Close()
	assert.Equal(t, http.StatusOK, jsResp.StatusCode)

	summaryResp, err := http.Get(srv.URL + "/api/dashboard/summary")
	require.NoError(t, err)
	defer summaryResp.Body.Close()
	assert.Equal(t, http.StatusOK, summaryResp.StatusCode)

	var summary dashboardSummaryResponse
	require.NoError(t, json.NewDecoder(summaryResp.Body).Decode(&summary))
	assert.False(t, summary.Config.Dashboard.AuthEnabled)
	assert.Equal(t, "/dashboard", summary.Config.Dashboard.Path)
	assert.Equal(t, "/api/dashboard", summary.Config.Dashboard.APIPrefix)

	rulesResp, err := http.Get(srv.URL + "/api/dashboard/rules")
	require.NoError(t, err)
	defer rulesResp.Body.Close()
	assert.Equal(t, http.StatusOK, rulesResp.StatusCode)
	var rules dashboardRulesResponse
	require.NoError(t, json.NewDecoder(rulesResp.Body).Decode(&rules))
	assert.Equal(t, 2, rules.TotalRuleSets)
	assert.Equal(t, 111, rules.TotalRules)
}

func TestDashboardEnabled_BasicAuth(t *testing.T) {
	srv := buildDashboardTestServer(t, DashboardOptions{
		Enabled:        true,
		Path:           "/dashboard",
		APIPrefix:      "/api/dashboard",
		RefreshSeconds: 5,
		Auth: DashboardAuthOptions{
			Enabled:  true,
			Username: "admin",
			Password: "secret",
		},
	})
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/dashboard")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("WWW-Authenticate"), "Basic")

	wrongReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/api/dashboard/summary", nil)
	require.NoError(t, err)
	wrongReq.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("admin:wrong")))
	wrongResp, err := http.DefaultClient.Do(wrongReq)
	require.NoError(t, err)
	defer wrongResp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, wrongResp.StatusCode)

	okReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/api/dashboard/summary", nil)
	require.NoError(t, err)
	okReq.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("admin:secret")))
	okResp, err := http.DefaultClient.Do(okReq)
	require.NoError(t, err)
	defer okResp.Body.Close()
	assert.Equal(t, http.StatusOK, okResp.StatusCode)
}
