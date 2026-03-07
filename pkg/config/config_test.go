package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefault(t *testing.T) {
	cfg := Default()
	assert.Equal(t, 0.5, cfg.Detector.Threshold)
	assert.Equal(t, "low", cfg.Detector.MinSeverity)
	assert.Equal(t, 100, cfg.Detector.TimeoutMs)
	assert.Equal(t, "weighted", cfg.Detector.Strategy)
	assert.Equal(t, "", cfg.Detector.MLModelPath)
	assert.Equal(t, 0.85, cfg.Detector.MLThreshold)
	assert.Equal(t, 0.6, cfg.Detector.Weights.Regex)
	assert.Equal(t, 0.4, cfg.Detector.Weights.ML)
	assert.True(t, cfg.Detector.AdaptiveThreshold.Enabled)
	assert.Equal(t, 0.25, cfg.Detector.AdaptiveThreshold.MinThreshold)
	assert.Equal(t, 0.2, cfg.Detector.AdaptiveThreshold.EWMAAlpha)
	assert.Equal(t, ":8080", cfg.Proxy.Listen)
	assert.Equal(t, "block", cfg.Proxy.Action)
	assert.True(t, cfg.Proxy.RateLimit.Enabled)
	assert.Equal(t, 120, cfg.Proxy.RateLimit.RequestsPerMinute)
	assert.Equal(t, 30, cfg.Proxy.RateLimit.Burst)
	assert.Equal(t, "X-Forwarded-For", cfg.Proxy.RateLimit.KeyHeader)
	assert.False(t, cfg.Dashboard.Enabled)
	assert.Equal(t, "/dashboard", cfg.Dashboard.Path)
	assert.Equal(t, "/api/dashboard", cfg.Dashboard.APIPrefix)
	assert.Equal(t, 5, cfg.Dashboard.RefreshSeconds)
	assert.False(t, cfg.Dashboard.Auth.Enabled)
	assert.False(t, cfg.Dashboard.RuleManagement.Enabled)
	assert.Equal(t, ":8443", cfg.Webhook.Listen)
	assert.Equal(t, `(?i)pif-proxy`, cfg.Webhook.PIFHostPattern)
	assert.Equal(t, "info", cfg.Logging.Level)
	assert.False(t, cfg.Logging.LogPrompts)
	assert.Len(t, cfg.Rules.Paths, 3)
}

func TestLoad_FromFile(t *testing.T) {
	configDir := findProjectRoot(t)
	cfgPath := filepath.Join(configDir, "config.yaml")

	cfg, err := Load(cfgPath)
	require.NoError(t, err)
	assert.Equal(t, 0.5, cfg.Detector.Threshold)
	assert.Equal(t, ":8080", cfg.Proxy.Listen)
	assert.Equal(t, "https://api.openai.com", cfg.Proxy.Target)
	assert.Equal(t, 0.85, cfg.Detector.MLThreshold)
	assert.Equal(t, 0.6, cfg.Detector.Weights.Regex)
	assert.Equal(t, 0.4, cfg.Detector.Weights.ML)
	assert.True(t, cfg.Proxy.RateLimit.Enabled)
	assert.Equal(t, 0.25, cfg.Detector.AdaptiveThreshold.MinThreshold)
}

func TestLoad_NoFile(t *testing.T) {
	cfg, err := Load("")
	require.NoError(t, err)
	assert.Equal(t, 0.5, cfg.Detector.Threshold) // should use defaults
}

func TestLoad_NonexistentFile(t *testing.T) {
	_, err := Load("/nonexistent/config.yaml")
	assert.Error(t, err)
}

func TestLoad_EnvOverride(t *testing.T) {
	t.Setenv("PIF_DETECTOR_THRESHOLD", "0.8")
	t.Setenv("PIF_PROXY_LISTEN", ":9090")
	t.Setenv("PIF_PROXY_RATE_LIMIT_REQUESTS_PER_MINUTE", "240")
	t.Setenv("PIF_DETECTOR_ADAPTIVE_THRESHOLD_EWMA_ALPHA", "0.3")
	t.Setenv("PIF_DASHBOARD_ENABLED", "true")
	t.Setenv("PIF_DASHBOARD_AUTH_ENABLED", "true")
	t.Setenv("PIF_DASHBOARD_AUTH_USERNAME", "admin")
	t.Setenv("PIF_DASHBOARD_AUTH_PASSWORD", "secret")
	t.Setenv("PIF_DASHBOARD_RULE_MANAGEMENT_ENABLED", "true")

	cfg, err := Load("")
	require.NoError(t, err)
	assert.Equal(t, 0.8, cfg.Detector.Threshold)
	assert.Equal(t, ":9090", cfg.Proxy.Listen)
	assert.Equal(t, 240, cfg.Proxy.RateLimit.RequestsPerMinute)
	assert.Equal(t, 0.3, cfg.Detector.AdaptiveThreshold.EWMAAlpha)
	assert.True(t, cfg.Dashboard.Enabled)
	assert.True(t, cfg.Dashboard.Auth.Enabled)
	assert.Equal(t, "admin", cfg.Dashboard.Auth.Username)
	assert.Equal(t, "secret", cfg.Dashboard.Auth.Password)
	assert.True(t, cfg.Dashboard.RuleManagement.Enabled)
}

func TestLoad_MLEnvOverride(t *testing.T) {
	t.Setenv("PIF_DETECTOR_ML_MODEL_PATH", "/path/to/model")
	t.Setenv("PIF_DETECTOR_ML_THRESHOLD", "0.90")

	cfg, err := Load("")
	require.NoError(t, err)
	assert.Equal(t, "/path/to/model", cfg.Detector.MLModelPath)
	assert.Equal(t, 0.90, cfg.Detector.MLThreshold)
}

func TestLoad_CustomConfig(t *testing.T) {
	content := `
detector:
  threshold: 0.9
  min_severity: "high"
  timeout_ms: 20
  adaptive_threshold:
    enabled: false
    min_threshold: 0.4
    ewma_alpha: 0.1
proxy:
  listen: ":3000"
  target: "https://api.anthropic.com"
  action: "flag"
  rate_limit:
    enabled: false
    requests_per_minute: 30
    burst: 10
dashboard:
  enabled: true
  path: "/admin/pif"
  api_prefix: "/admin/pif/api"
  refresh_seconds: 3
  auth:
    enabled: true
    username: "ops"
    password: "pass"
  rule_management:
    enabled: true
webhook:
  pif_host_pattern: "(?i)my-pif"
`
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "custom.yaml")
	err := os.WriteFile(cfgPath, []byte(content), 0644)
	require.NoError(t, err)

	cfg, err := Load(cfgPath)
	require.NoError(t, err)
	assert.Equal(t, 0.9, cfg.Detector.Threshold)
	assert.Equal(t, "high", cfg.Detector.MinSeverity)
	assert.Equal(t, 20, cfg.Detector.TimeoutMs)
	assert.Equal(t, ":3000", cfg.Proxy.Listen)
	assert.Equal(t, "https://api.anthropic.com", cfg.Proxy.Target)
	assert.Equal(t, "flag", cfg.Proxy.Action)
	assert.False(t, cfg.Proxy.RateLimit.Enabled)
	assert.Equal(t, 30, cfg.Proxy.RateLimit.RequestsPerMinute)
	assert.Equal(t, 10, cfg.Proxy.RateLimit.Burst)
	assert.True(t, cfg.Dashboard.Enabled)
	assert.Equal(t, "/admin/pif", cfg.Dashboard.Path)
	assert.Equal(t, "/admin/pif/api", cfg.Dashboard.APIPrefix)
	assert.Equal(t, 3, cfg.Dashboard.RefreshSeconds)
	assert.True(t, cfg.Dashboard.Auth.Enabled)
	assert.Equal(t, "ops", cfg.Dashboard.Auth.Username)
	assert.Equal(t, "pass", cfg.Dashboard.Auth.Password)
	assert.True(t, cfg.Dashboard.RuleManagement.Enabled)
	assert.False(t, cfg.Detector.AdaptiveThreshold.Enabled)
	assert.Equal(t, 0.4, cfg.Detector.AdaptiveThreshold.MinThreshold)
	assert.Equal(t, 0.1, cfg.Detector.AdaptiveThreshold.EWMAAlpha)
	assert.Equal(t, "(?i)my-pif", cfg.Webhook.PIFHostPattern)
}

func findProjectRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	require.NoError(t, err)

	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find project root")
		}
		dir = parent
	}
}
