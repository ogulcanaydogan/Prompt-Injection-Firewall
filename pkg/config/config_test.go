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
	assert.False(t, cfg.Alerting.Enabled)
	assert.Equal(t, 1024, cfg.Alerting.QueueSize)
	assert.True(t, cfg.Alerting.Events.Block)
	assert.True(t, cfg.Alerting.Events.RateLimit)
	assert.True(t, cfg.Alerting.Events.ScanError)
	assert.Equal(t, 60, cfg.Alerting.Throttle.WindowSeconds)
	assert.False(t, cfg.Alerting.Webhook.Enabled)
	assert.Equal(t, "3s", cfg.Alerting.Webhook.Timeout)
	assert.Equal(t, 3, cfg.Alerting.Webhook.MaxRetries)
	assert.Equal(t, 200, cfg.Alerting.Webhook.BackoffInitialMs)
	assert.False(t, cfg.Alerting.Slack.Enabled)
	assert.Equal(t, "3s", cfg.Alerting.Slack.Timeout)
	assert.False(t, cfg.Alerting.PagerDuty.Enabled)
	assert.Equal(t, "https://events.pagerduty.com/v2/enqueue", cfg.Alerting.PagerDuty.URL)
	assert.Equal(t, "", cfg.Alerting.PagerDuty.RoutingKey)
	assert.Equal(t, "3s", cfg.Alerting.PagerDuty.Timeout)
	assert.Equal(t, 3, cfg.Alerting.PagerDuty.MaxRetries)
	assert.Equal(t, 200, cfg.Alerting.PagerDuty.BackoffInitialMs)
	assert.Equal(t, "prompt-injection-firewall", cfg.Alerting.PagerDuty.Source)
	assert.Equal(t, "proxy", cfg.Alerting.PagerDuty.Component)
	assert.Equal(t, "pif", cfg.Alerting.PagerDuty.Group)
	assert.Equal(t, "security", cfg.Alerting.PagerDuty.Class)
	assert.False(t, cfg.Tenancy.Enabled)
	assert.Equal(t, "X-PIF-Tenant", cfg.Tenancy.Header)
	assert.Equal(t, "default", cfg.Tenancy.DefaultTenant)
	assert.Empty(t, cfg.Tenancy.Tenants)
	assert.False(t, cfg.Replay.Enabled)
	assert.Equal(t, "data/replay/events.jsonl", cfg.Replay.StoragePath)
	assert.Equal(t, 50, cfg.Replay.MaxFileSizeMB)
	assert.Equal(t, 5, cfg.Replay.MaxFiles)
	assert.True(t, cfg.Replay.CaptureEvents.Block)
	assert.True(t, cfg.Replay.CaptureEvents.RateLimit)
	assert.True(t, cfg.Replay.CaptureEvents.ScanError)
	assert.True(t, cfg.Replay.CaptureEvents.Flag)
	assert.True(t, cfg.Replay.RedactPromptContent)
	assert.Equal(t, 512, cfg.Replay.MaxPromptChars)
	assert.False(t, cfg.Marketplace.Enabled)
	assert.Equal(t, ".cache/pif-marketplace", cfg.Marketplace.CacheDir)
	assert.Equal(t, "rules/community", cfg.Marketplace.InstallDir)
	assert.Equal(t, 60, cfg.Marketplace.RefreshIntervalMinutes)
	assert.True(t, cfg.Marketplace.RequireChecksum)
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
	t.Setenv("PIF_ALERTING_ENABLED", "true")
	t.Setenv("PIF_ALERTING_QUEUE_SIZE", "2048")
	t.Setenv("PIF_ALERTING_EVENTS_BLOCK", "false")
	t.Setenv("PIF_ALERTING_EVENTS_RATE_LIMIT", "true")
	t.Setenv("PIF_ALERTING_EVENTS_SCAN_ERROR", "true")
	t.Setenv("PIF_ALERTING_WEBHOOK_ENABLED", "true")
	t.Setenv("PIF_ALERTING_WEBHOOK_URL", "https://example.com/hook")
	t.Setenv("PIF_ALERTING_WEBHOOK_AUTH_BEARER_TOKEN", "topsecret")
	t.Setenv("PIF_ALERTING_SLACK_ENABLED", "true")
	t.Setenv("PIF_ALERTING_SLACK_INCOMING_WEBHOOK_URL", "https://hooks.slack.com/services/T/B/X")
	t.Setenv("PIF_ALERTING_PAGERDUTY_ENABLED", "true")
	t.Setenv("PIF_ALERTING_PAGERDUTY_URL", "https://events.pagerduty.com/v2/enqueue")
	t.Setenv("PIF_ALERTING_PAGERDUTY_ROUTING_KEY", "pd-routing-key")
	t.Setenv("PIF_ALERTING_PAGERDUTY_TIMEOUT", "4s")
	t.Setenv("PIF_ALERTING_PAGERDUTY_MAX_RETRIES", "5")
	t.Setenv("PIF_ALERTING_PAGERDUTY_BACKOFF_INITIAL_MS", "250")
	t.Setenv("PIF_ALERTING_PAGERDUTY_SOURCE", "pif-prod")
	t.Setenv("PIF_ALERTING_PAGERDUTY_COMPONENT", "proxy-main")
	t.Setenv("PIF_ALERTING_PAGERDUTY_GROUP", "secops")
	t.Setenv("PIF_ALERTING_PAGERDUTY_CLASS", "firewall")
	t.Setenv("PIF_TENANCY_ENABLED", "true")
	t.Setenv("PIF_TENANCY_HEADER", "X-Org-ID")
	t.Setenv("PIF_TENANCY_DEFAULT_TENANT", "acme")
	t.Setenv("PIF_REPLAY_ENABLED", "true")
	t.Setenv("PIF_REPLAY_STORAGE_PATH", "tmp/replay.jsonl")
	t.Setenv("PIF_REPLAY_MAX_FILE_SIZE_MB", "8")
	t.Setenv("PIF_REPLAY_MAX_FILES", "4")
	t.Setenv("PIF_REPLAY_CAPTURE_EVENTS_FLAG", "false")
	t.Setenv("PIF_REPLAY_REDACT_PROMPT_CONTENT", "false")
	t.Setenv("PIF_REPLAY_MAX_PROMPT_CHARS", "256")
	t.Setenv("PIF_MARKETPLACE_ENABLED", "true")
	t.Setenv("PIF_MARKETPLACE_INDEX_URL", "https://example.com/index.json")
	t.Setenv("PIF_MARKETPLACE_CACHE_DIR", ".cache/market")
	t.Setenv("PIF_MARKETPLACE_INSTALL_DIR", "rules/community")
	t.Setenv("PIF_MARKETPLACE_REFRESH_INTERVAL_MINUTES", "15")
	t.Setenv("PIF_MARKETPLACE_REQUIRE_CHECKSUM", "false")

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
	assert.True(t, cfg.Alerting.Enabled)
	assert.Equal(t, 2048, cfg.Alerting.QueueSize)
	assert.False(t, cfg.Alerting.Events.Block)
	assert.True(t, cfg.Alerting.Events.RateLimit)
	assert.True(t, cfg.Alerting.Events.ScanError)
	assert.True(t, cfg.Alerting.Webhook.Enabled)
	assert.Equal(t, "https://example.com/hook", cfg.Alerting.Webhook.URL)
	assert.Equal(t, "topsecret", cfg.Alerting.Webhook.AuthBearerToken)
	assert.True(t, cfg.Alerting.Slack.Enabled)
	assert.Equal(t, "https://hooks.slack.com/services/T/B/X", cfg.Alerting.Slack.IncomingWebhookURL)
	assert.True(t, cfg.Alerting.PagerDuty.Enabled)
	assert.Equal(t, "https://events.pagerduty.com/v2/enqueue", cfg.Alerting.PagerDuty.URL)
	assert.Equal(t, "pd-routing-key", cfg.Alerting.PagerDuty.RoutingKey)
	assert.Equal(t, "4s", cfg.Alerting.PagerDuty.Timeout)
	assert.Equal(t, 5, cfg.Alerting.PagerDuty.MaxRetries)
	assert.Equal(t, 250, cfg.Alerting.PagerDuty.BackoffInitialMs)
	assert.Equal(t, "pif-prod", cfg.Alerting.PagerDuty.Source)
	assert.Equal(t, "proxy-main", cfg.Alerting.PagerDuty.Component)
	assert.Equal(t, "secops", cfg.Alerting.PagerDuty.Group)
	assert.Equal(t, "firewall", cfg.Alerting.PagerDuty.Class)
	assert.True(t, cfg.Tenancy.Enabled)
	assert.Equal(t, "X-Org-ID", cfg.Tenancy.Header)
	assert.Equal(t, "acme", cfg.Tenancy.DefaultTenant)
	assert.True(t, cfg.Replay.Enabled)
	assert.Equal(t, "tmp/replay.jsonl", cfg.Replay.StoragePath)
	assert.Equal(t, 8, cfg.Replay.MaxFileSizeMB)
	assert.Equal(t, 4, cfg.Replay.MaxFiles)
	assert.False(t, cfg.Replay.CaptureEvents.Flag)
	assert.False(t, cfg.Replay.RedactPromptContent)
	assert.Equal(t, 256, cfg.Replay.MaxPromptChars)
	assert.True(t, cfg.Marketplace.Enabled)
	assert.Equal(t, "https://example.com/index.json", cfg.Marketplace.IndexURL)
	assert.Equal(t, ".cache/market", cfg.Marketplace.CacheDir)
	assert.Equal(t, "rules/community", cfg.Marketplace.InstallDir)
	assert.Equal(t, 15, cfg.Marketplace.RefreshIntervalMinutes)
	assert.False(t, cfg.Marketplace.RequireChecksum)
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
alerting:
  enabled: true
  queue_size: 128
  events:
    block: true
    rate_limit: true
    scan_error: false
  throttle:
    window_seconds: 30
  webhook:
    enabled: true
    url: "https://alerts.example.com/pif"
    timeout: "2s"
    max_retries: 2
    backoff_initial_ms: 100
    auth_bearer_token: "abc123"
  slack:
    enabled: true
    incoming_webhook_url: "https://hooks.slack.com/services/T/B/X"
    timeout: "2s"
    max_retries: 2
    backoff_initial_ms: 100
  pagerduty:
    enabled: true
    url: "https://events.pagerduty.com/v2/enqueue"
    routing_key: "pd-routing-key"
    timeout: "4s"
    max_retries: 4
    backoff_initial_ms: 250
    source: "pif-prod"
    component: "proxy-main"
    group: "secops"
    class: "firewall"
tenancy:
  enabled: true
  header: "X-PIF-Tenant"
  default_tenant: "default"
  tenants:
    default:
      policy:
        action: "block"
        threshold: 0.5
        rate_limit:
          requests_per_minute: 60
          burst: 10
        adaptive_threshold:
          enabled: true
          min_threshold: 0.2
          ewma_alpha: 0.3
replay:
  enabled: true
  storage_path: "data/replay/events.jsonl"
  max_file_size_mb: 20
  max_files: 3
  capture_events:
    block: true
    rate_limit: true
    scan_error: true
    flag: false
  redact_prompt_content: false
  max_prompt_chars: 400
marketplace:
  enabled: true
  index_url: "https://example.com/index.json"
  cache_dir: ".cache/pif-marketplace"
  install_dir: "rules/community"
  refresh_interval_minutes: 30
  require_checksum: true
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
	assert.True(t, cfg.Alerting.Enabled)
	assert.Equal(t, 128, cfg.Alerting.QueueSize)
	assert.True(t, cfg.Alerting.Events.Block)
	assert.True(t, cfg.Alerting.Events.RateLimit)
	assert.False(t, cfg.Alerting.Events.ScanError)
	assert.Equal(t, 30, cfg.Alerting.Throttle.WindowSeconds)
	assert.True(t, cfg.Alerting.Webhook.Enabled)
	assert.Equal(t, "https://alerts.example.com/pif", cfg.Alerting.Webhook.URL)
	assert.Equal(t, "2s", cfg.Alerting.Webhook.Timeout)
	assert.Equal(t, 2, cfg.Alerting.Webhook.MaxRetries)
	assert.Equal(t, 100, cfg.Alerting.Webhook.BackoffInitialMs)
	assert.Equal(t, "abc123", cfg.Alerting.Webhook.AuthBearerToken)
	assert.True(t, cfg.Alerting.Slack.Enabled)
	assert.Equal(t, "https://hooks.slack.com/services/T/B/X", cfg.Alerting.Slack.IncomingWebhookURL)
	assert.Equal(t, "2s", cfg.Alerting.Slack.Timeout)
	assert.Equal(t, 2, cfg.Alerting.Slack.MaxRetries)
	assert.Equal(t, 100, cfg.Alerting.Slack.BackoffInitialMs)
	assert.True(t, cfg.Alerting.PagerDuty.Enabled)
	assert.Equal(t, "https://events.pagerduty.com/v2/enqueue", cfg.Alerting.PagerDuty.URL)
	assert.Equal(t, "pd-routing-key", cfg.Alerting.PagerDuty.RoutingKey)
	assert.Equal(t, "4s", cfg.Alerting.PagerDuty.Timeout)
	assert.Equal(t, 4, cfg.Alerting.PagerDuty.MaxRetries)
	assert.Equal(t, 250, cfg.Alerting.PagerDuty.BackoffInitialMs)
	assert.Equal(t, "pif-prod", cfg.Alerting.PagerDuty.Source)
	assert.Equal(t, "proxy-main", cfg.Alerting.PagerDuty.Component)
	assert.Equal(t, "secops", cfg.Alerting.PagerDuty.Group)
	assert.Equal(t, "firewall", cfg.Alerting.PagerDuty.Class)
	assert.True(t, cfg.Tenancy.Enabled)
	assert.Equal(t, "X-PIF-Tenant", cfg.Tenancy.Header)
	assert.Equal(t, "default", cfg.Tenancy.DefaultTenant)
	require.Contains(t, cfg.Tenancy.Tenants, "default")
	assert.Equal(t, "block", cfg.Tenancy.Tenants["default"].Policy.Action)
	assert.Equal(t, 0.5, cfg.Tenancy.Tenants["default"].Policy.Threshold)
	assert.Equal(t, 60, cfg.Tenancy.Tenants["default"].Policy.RateLimit.RequestsPerMinute)
	assert.Equal(t, 10, cfg.Tenancy.Tenants["default"].Policy.RateLimit.Burst)
	require.NotNil(t, cfg.Tenancy.Tenants["default"].Policy.AdaptiveThreshold.Enabled)
	assert.True(t, *cfg.Tenancy.Tenants["default"].Policy.AdaptiveThreshold.Enabled)
	assert.Equal(t, 0.2, cfg.Tenancy.Tenants["default"].Policy.AdaptiveThreshold.MinThreshold)
	assert.Equal(t, 0.3, cfg.Tenancy.Tenants["default"].Policy.AdaptiveThreshold.EWMAAlpha)
	assert.True(t, cfg.Replay.Enabled)
	assert.Equal(t, "data/replay/events.jsonl", cfg.Replay.StoragePath)
	assert.Equal(t, 20, cfg.Replay.MaxFileSizeMB)
	assert.Equal(t, 3, cfg.Replay.MaxFiles)
	assert.True(t, cfg.Replay.CaptureEvents.Block)
	assert.True(t, cfg.Replay.CaptureEvents.RateLimit)
	assert.True(t, cfg.Replay.CaptureEvents.ScanError)
	assert.False(t, cfg.Replay.CaptureEvents.Flag)
	assert.False(t, cfg.Replay.RedactPromptContent)
	assert.Equal(t, 400, cfg.Replay.MaxPromptChars)
	assert.True(t, cfg.Marketplace.Enabled)
	assert.Equal(t, "https://example.com/index.json", cfg.Marketplace.IndexURL)
	assert.Equal(t, ".cache/pif-marketplace", cfg.Marketplace.CacheDir)
	assert.Equal(t, "rules/community", cfg.Marketplace.InstallDir)
	assert.Equal(t, 30, cfg.Marketplace.RefreshIntervalMinutes)
	assert.True(t, cfg.Marketplace.RequireChecksum)
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
