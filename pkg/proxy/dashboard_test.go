package proxy

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ogulcanaydogan/Prompt-Injection-Firewall/pkg/detector"
	"github.com/ogulcanaydogan/Prompt-Injection-Firewall/pkg/rules"
)

func buildDashboardTestServer(t *testing.T, dashboard DashboardOptions) (*httptest.Server, RuleManager) {
	t.Helper()

	tmp := t.TempDir()
	baseRulesPath := filepath.Join(tmp, "base.yaml")
	customRulesPath := filepath.Join(tmp, "custom.yaml")
	writeRuleSetFixture(t, baseRulesPath, rules.RuleSet{
		Name:    "base",
		Version: "1.0.0",
		Rules: []rules.Rule{
			{
				ID:            "BASE-001",
				Name:          "base",
				Description:   "base rule",
				Category:      "prompt_injection",
				Severity:      int(detector.SeverityMedium),
				Pattern:       "base_attack",
				Enabled:       true,
				CaseSensitive: false,
			},
		},
	})

	ruleManager, err := NewRuntimeRuleManager(RuntimeRuleManagerOptions{
		RulePaths:       []string{baseRulesPath},
		CustomPaths:     []string{customRulesPath},
		DetectorFactory: testRuleManagerDetectorFactory,
	})
	require.NoError(t, err)

	snapshot := ruleManager.Snapshot()
	metrics := NewMetrics()
	opts := ServerOptions{
		TargetURL:     "http://upstream.local",
		Listen:        ":0",
		Action:        "block",
		Threshold:     0.5,
		Metrics:       metrics,
		Dashboard:     dashboard,
		RuleInventory: snapshot.RuleSets,
		RuleManager:   ruleManager,
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

	middleware := ScanMiddlewareWithOptions(ruleManager.Detector(), ParseAction(opts.Action), MiddlewareOptions{
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

	return httptest.NewServer(mux), ruleManager
}

func TestDashboardDisabled_ReturnsNotFound(t *testing.T) {
	srv, _ := buildDashboardTestServer(t, DashboardOptions{
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

func TestDashboardEnabled_NoAuth_ReadOnlyWhenRuleManagementDisabled(t *testing.T) {
	srv, _ := buildDashboardTestServer(t, DashboardOptions{
		Enabled:               true,
		Path:                  "/dashboard",
		APIPrefix:             "/api/dashboard",
		RefreshSeconds:        5,
		RuleManagementEnabled: false,
		Auth:                  DashboardAuthOptions{Enabled: false},
	})
	defer srv.Close()

	readResp, err := http.Get(srv.URL + "/api/dashboard/rules")
	require.NoError(t, err)
	defer readResp.Body.Close()
	assert.Equal(t, http.StatusOK, readResp.StatusCode)

	postReq, err := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL+"/api/dashboard/rules", jsonBody(`{"rule":{"id":"X","name":"n","description":"d","category":"prompt_injection","severity":2,"pattern":"x","enabled":true}}`))
	require.NoError(t, err)
	postReq.Header.Set("Content-Type", "application/json")
	postResp, err := http.DefaultClient.Do(postReq)
	require.NoError(t, err)
	defer postResp.Body.Close()
	assert.Equal(t, http.StatusNotFound, postResp.StatusCode)
}

func TestDashboardEnabled_RuleManagementEnabledButAuthOff_ReturnsForbiddenOnWrite(t *testing.T) {
	srv, _ := buildDashboardTestServer(t, DashboardOptions{
		Enabled:               true,
		Path:                  "/dashboard",
		APIPrefix:             "/api/dashboard",
		RefreshSeconds:        5,
		RuleManagementEnabled: true,
		Auth:                  DashboardAuthOptions{Enabled: false},
	})
	defer srv.Close()

	postReq, err := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL+"/api/dashboard/rules", jsonBody(`{"rule":{"id":"X","name":"n","description":"d","category":"prompt_injection","severity":2,"pattern":"x","enabled":true}}`))
	require.NoError(t, err)
	postReq.Header.Set("Content-Type", "application/json")
	postResp, err := http.DefaultClient.Do(postReq)
	require.NoError(t, err)
	defer postResp.Body.Close()
	assert.Equal(t, http.StatusForbidden, postResp.StatusCode)
}

func TestDashboardEnabled_BasicAuthAndRuleCRUD(t *testing.T) {
	srv, ruleManager := buildDashboardTestServer(t, DashboardOptions{
		Enabled:               true,
		Path:                  "/dashboard",
		APIPrefix:             "/api/dashboard",
		RefreshSeconds:        5,
		RuleManagementEnabled: true,
		Auth: DashboardAuthOptions{
			Enabled:  true,
			Username: "admin",
			Password: "secret",
		},
	})
	defer srv.Close()

	noCredResp, err := http.Get(srv.URL + "/api/dashboard/rules")
	require.NoError(t, err)
	defer noCredResp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, noCredResp.StatusCode)

	wrongReq, err := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL+"/api/dashboard/rules", jsonBody(`{"rule":{"id":"CUSTOM-1","name":"c","description":"d","category":"prompt_injection","severity":2,"pattern":"custom_hit","enabled":true}}`))
	require.NoError(t, err)
	wrongReq.Header.Set("Content-Type", "application/json")
	wrongReq.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("admin:wrong")))
	wrongResp, err := http.DefaultClient.Do(wrongReq)
	require.NoError(t, err)
	defer wrongResp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, wrongResp.StatusCode)

	authHeader := "Basic " + base64.StdEncoding.EncodeToString([]byte("admin:secret"))

	preCreateStatus := sendProxyPrompt(t, srv.URL, "custom_hit")
	assert.Equal(t, http.StatusOK, preCreateStatus)

	createReq, err := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL+"/api/dashboard/rules", jsonBody(`{"rule":{"id":"CUSTOM-1","name":"c","description":"d","category":"prompt_injection","severity":2,"pattern":"custom_hit","enabled":true}}`))
	require.NoError(t, err)
	createReq.Header.Set("Content-Type", "application/json")
	createReq.Header.Set("Authorization", authHeader)
	createResp, err := http.DefaultClient.Do(createReq)
	require.NoError(t, err)
	defer createResp.Body.Close()
	assert.Equal(t, http.StatusCreated, createResp.StatusCode)

	postCreateStatus := sendProxyPrompt(t, srv.URL, "custom_hit")
	assert.Equal(t, http.StatusForbidden, postCreateStatus)

	updateReq, err := http.NewRequestWithContext(context.Background(), http.MethodPut, srv.URL+"/api/dashboard/rules/CUSTOM-1", jsonBody(`{"rule":{"name":"c2","description":"d2","category":"prompt_injection","severity":3,"pattern":"custom_hit_v2","enabled":true}}`))
	require.NoError(t, err)
	updateReq.Header.Set("Content-Type", "application/json")
	updateReq.Header.Set("Authorization", authHeader)
	updateResp, err := http.DefaultClient.Do(updateReq)
	require.NoError(t, err)
	defer updateResp.Body.Close()
	assert.Equal(t, http.StatusOK, updateResp.StatusCode)

	postUpdateOldPattern := sendProxyPrompt(t, srv.URL, "custom_hit")
	assert.Equal(t, http.StatusOK, postUpdateOldPattern)
	postUpdateNewPattern := sendProxyPrompt(t, srv.URL, "custom_hit_v2")
	assert.Equal(t, http.StatusForbidden, postUpdateNewPattern)

	deleteReq, err := http.NewRequestWithContext(context.Background(), http.MethodDelete, srv.URL+"/api/dashboard/rules/CUSTOM-1", nil)
	require.NoError(t, err)
	deleteReq.Header.Set("Authorization", authHeader)
	deleteResp, err := http.DefaultClient.Do(deleteReq)
	require.NoError(t, err)
	defer deleteResp.Body.Close()
	assert.Equal(t, http.StatusOK, deleteResp.StatusCode)

	postDeleteStatus := sendProxyPrompt(t, srv.URL, "custom_hit_v2")
	assert.Equal(t, http.StatusOK, postDeleteStatus)

	summaryReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/api/dashboard/summary", nil)
	require.NoError(t, err)
	summaryReq.Header.Set("Authorization", authHeader)
	summaryResp, err := http.DefaultClient.Do(summaryReq)
	require.NoError(t, err)
	defer summaryResp.Body.Close()
	assert.Equal(t, http.StatusOK, summaryResp.StatusCode)

	var summary dashboardSummaryResponse
	require.NoError(t, json.NewDecoder(summaryResp.Body).Decode(&summary))
	assert.True(t, summary.Config.Dashboard.AuthEnabled)
	assert.True(t, summary.Config.Dashboard.RuleManagementEnabled)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	scan, err := ruleManager.Detector().Scan(ctx, detector.ScanInput{Text: "custom_hit_v2"})
	require.NoError(t, err)
	assert.True(t, scan.Clean)
}

func jsonBody(body string) *strings.Reader {
	return strings.NewReader(body)
}

func sendProxyPrompt(t *testing.T, baseURL, content string) int {
	t.Helper()

	payload := fmt.Sprintf(`{"model":"gpt-4","messages":[{"role":"user","content":"%s"}]}`, content)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, baseURL+"/v1/chat/completions", strings.NewReader(payload))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	return resp.StatusCode
}
