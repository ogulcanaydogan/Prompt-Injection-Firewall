package cli

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ogulcanaydogan/Prompt-Injection-Firewall/pkg/config"
	"github.com/ogulcanaydogan/Prompt-Injection-Firewall/pkg/detector"
	"github.com/ogulcanaydogan/Prompt-Injection-Firewall/pkg/rules"
)

func TestResolveProxyModelPath_Priority(t *testing.T) {
	origProxyModel := proxyModel
	origScanModel := scanModel
	defer func() {
		proxyModel = origProxyModel
		scanModel = origScanModel
	}()

	cfg := config.Default()
	cfg.Detector.MLModelPath = "/cfg/model"

	proxyModel = "/cli/model"
	got := resolveProxyModelPath(cfg)
	assert.Equal(t, "/cli/model", got)
	assert.Equal(t, "/cli/model", scanModel)

	proxyModel = ""
	got = resolveProxyModelPath(cfg)
	assert.Equal(t, "/cfg/model", got)
	assert.Equal(t, "/cfg/model", scanModel)

	cfg.Detector.MLModelPath = ""
	got = resolveProxyModelPath(cfg)
	assert.Equal(t, "", got)
}

func TestBuildProxyDetectorFactory_RegexOnly(t *testing.T) {
	cfg := config.Default()
	cfg.Detector.Strategy = "any"
	cfg.Detector.TimeoutMs = 50

	factory := buildProxyDetectorFactory(cfg, "")
	ruleSets := []rules.RuleSet{
		{
			Name:    "test-rules",
			Version: "1.0.0",
			Rules: []rules.Rule{
				{
					ID:            "T-1",
					Name:          "test",
					Description:   "test rule",
					Category:      "prompt_injection",
					Severity:      int(detector.SeverityHigh),
					Pattern:       "hello_attack",
					Enabled:       true,
					CaseSensitive: false,
				},
			},
		},
	}

	d, err := factory(ruleSets)
	require.NoError(t, err)
	ens, ok := d.(*detector.EnsembleDetector)
	require.True(t, ok)
	assert.Equal(t, 1, ens.DetectorCount())

	res, err := d.Scan(testContext(t), detector.ScanInput{Text: "hello_attack"})
	require.NoError(t, err)
	assert.False(t, res.Clean)
}

func TestRunProxy_InvalidTimeouts(t *testing.T) {
	tmp := t.TempDir()
	cfgPathRead := filepath.Join(tmp, "bad-read.yaml")
	cfgPathWrite := filepath.Join(tmp, "bad-write.yaml")

	require.NoError(t, os.WriteFile(cfgPathRead, []byte(`
proxy:
  read_timeout: "bad"
`), 0644))
	require.NoError(t, os.WriteFile(cfgPathWrite, []byte(`
proxy:
  read_timeout: "10s"
  write_timeout: "bad"
`), 0644))

	origCfgFile := cfgFile
	origProxyTarget := proxyTarget
	origProxyListen := proxyListen
	origProxyAction := proxyAction
	origProxyModel := proxyModel
	origScanModel := scanModel
	defer func() {
		cfgFile = origCfgFile
		proxyTarget = origProxyTarget
		proxyListen = origProxyListen
		proxyAction = origProxyAction
		proxyModel = origProxyModel
		scanModel = origScanModel
	}()

	cmd := newProxyCmd()

	cfgFile = cfgPathRead
	err := runProxy(cmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parsing proxy.read_timeout")

	cfgFile = cfgPathWrite
	err = runProxy(cmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parsing proxy.write_timeout")
}

func TestParseAlertingOptions(t *testing.T) {
	cfg := config.Default()
	cfg.Alerting.Enabled = true
	cfg.Alerting.QueueSize = 256
	cfg.Alerting.Events.Block = true
	cfg.Alerting.Events.RateLimit = true
	cfg.Alerting.Events.ScanError = false
	cfg.Alerting.Throttle.WindowSeconds = 45
	cfg.Alerting.Webhook.Enabled = true
	cfg.Alerting.Webhook.URL = "https://example.com/hook"
	cfg.Alerting.Webhook.Timeout = "5s"
	cfg.Alerting.Webhook.MaxRetries = 4
	cfg.Alerting.Webhook.BackoffInitialMs = 150
	cfg.Alerting.Webhook.AuthBearerToken = "token"
	cfg.Alerting.Slack.Enabled = true
	cfg.Alerting.Slack.IncomingWebhookURL = "https://hooks.slack.test/abc"
	cfg.Alerting.Slack.Timeout = "4s"
	cfg.Alerting.Slack.MaxRetries = 2
	cfg.Alerting.Slack.BackoffInitialMs = 300
	cfg.Alerting.PagerDuty.Enabled = true
	cfg.Alerting.PagerDuty.URL = "https://events.pagerduty.com/v2/enqueue"
	cfg.Alerting.PagerDuty.RoutingKey = "pd-key"
	cfg.Alerting.PagerDuty.Timeout = "6s"
	cfg.Alerting.PagerDuty.MaxRetries = 5
	cfg.Alerting.PagerDuty.BackoffInitialMs = 350
	cfg.Alerting.PagerDuty.Source = "pif-prod"
	cfg.Alerting.PagerDuty.Component = "proxy-main"
	cfg.Alerting.PagerDuty.Group = "secops"
	cfg.Alerting.PagerDuty.Class = "firewall"

	opts, err := parseAlertingOptions(cfg)
	require.NoError(t, err)

	assert.True(t, opts.Enabled)
	assert.Equal(t, 256, opts.QueueSize)
	assert.True(t, opts.Events.Block)
	assert.True(t, opts.Events.RateLimit)
	assert.False(t, opts.Events.ScanError)
	assert.Equal(t, 45*time.Second, opts.ThrottleWindow)
	assert.True(t, opts.Webhook.Enabled)
	assert.Equal(t, "https://example.com/hook", opts.Webhook.URL)
	assert.Equal(t, 5*time.Second, opts.Webhook.Timeout)
	assert.Equal(t, 4, opts.Webhook.MaxRetries)
	assert.Equal(t, 150*time.Millisecond, opts.Webhook.BackoffInitial)
	assert.Equal(t, "token", opts.Webhook.AuthBearerToken)
	assert.True(t, opts.Slack.Enabled)
	assert.Equal(t, "https://hooks.slack.test/abc", opts.Slack.URL)
	assert.Equal(t, 4*time.Second, opts.Slack.Timeout)
	assert.Equal(t, 2, opts.Slack.MaxRetries)
	assert.Equal(t, 300*time.Millisecond, opts.Slack.BackoffInitial)
	assert.True(t, opts.PagerDuty.Enabled)
	assert.Equal(t, "https://events.pagerduty.com/v2/enqueue", opts.PagerDuty.URL)
	assert.Equal(t, "pd-key", opts.PagerDuty.RoutingKey)
	assert.Equal(t, 6*time.Second, opts.PagerDuty.Timeout)
	assert.Equal(t, 5, opts.PagerDuty.MaxRetries)
	assert.Equal(t, 350*time.Millisecond, opts.PagerDuty.BackoffInitial)
	assert.Equal(t, "pif-prod", opts.PagerDuty.Source)
	assert.Equal(t, "proxy-main", opts.PagerDuty.Component)
	assert.Equal(t, "secops", opts.PagerDuty.Group)
	assert.Equal(t, "firewall", opts.PagerDuty.Class)
}

func TestParseAlertingOptions_InvalidTimeout(t *testing.T) {
	cfg := config.Default()
	cfg.Alerting.Webhook.Timeout = "bad"

	_, err := parseAlertingOptions(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parsing alerting.webhook.timeout")

	cfg = config.Default()
	cfg.Alerting.Slack.Timeout = "bad"
	_, err = parseAlertingOptions(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parsing alerting.slack.timeout")

	cfg = config.Default()
	cfg.Alerting.PagerDuty.Timeout = "bad"
	_, err = parseAlertingOptions(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parsing alerting.pagerduty.timeout")
}

func TestParseTenancyReplayAndMarketplaceOptions(t *testing.T) {
	cfg := config.Default()
	cfg.Tenancy.Enabled = true
	cfg.Tenancy.Header = "X-Tenant"
	cfg.Tenancy.DefaultTenant = "default"
	adaptiveEnabled := false
	cfg.Tenancy.Tenants = map[string]config.TenantConfig{
		"team-a": {
			Policy: config.TenantPolicyConfig{
				Action:    "flag",
				Threshold: 0.72,
				RateLimit: config.TenantRateLimitConfig{
					RequestsPerMinute: 40,
					Burst:             10,
				},
				AdaptiveThreshold: config.TenantAdaptiveThresholdOverrideConfig{
					Enabled:      &adaptiveEnabled,
					MinThreshold: 0.3,
					EWMAAlpha:    0.5,
				},
			},
		},
	}
	cfg.Replay.Enabled = true
	cfg.Replay.StoragePath = "tmp/replay.jsonl"
	cfg.Replay.MaxFileSizeMB = 12
	cfg.Replay.MaxFiles = 2
	cfg.Replay.CaptureEvents.Flag = false
	cfg.Replay.RedactPromptContent = false
	cfg.Replay.MaxPromptChars = 128
	cfg.Marketplace.Enabled = true
	cfg.Marketplace.IndexURL = "https://example.com/index.json"
	cfg.Marketplace.CacheDir = ".cache/mp"
	cfg.Marketplace.InstallDir = "rules/community"
	cfg.Marketplace.RefreshIntervalMinutes = 15
	cfg.Marketplace.RequireChecksum = false

	tenancy := parseTenancyOptions(cfg)
	require.True(t, tenancy.Enabled)
	assert.Equal(t, "X-Tenant", tenancy.Header)
	assert.Equal(t, "default", tenancy.DefaultTenant)
	require.Contains(t, tenancy.Tenants, "team-a")
	assert.Equal(t, "flag", tenancy.Tenants["team-a"].Action)
	require.NotNil(t, tenancy.Tenants["team-a"].AdaptiveThreshold.Enabled)
	assert.False(t, *tenancy.Tenants["team-a"].AdaptiveThreshold.Enabled)
	assert.Equal(t, 0.3, tenancy.Tenants["team-a"].AdaptiveThreshold.MinThreshold)
	assert.Equal(t, 0.5, tenancy.Tenants["team-a"].AdaptiveThreshold.EWMAAlpha)

	replay := parseReplayOptions(cfg)
	assert.True(t, replay.Enabled)
	assert.Equal(t, "tmp/replay.jsonl", replay.StoragePath)
	assert.Equal(t, 12, replay.MaxFileSizeMB)
	assert.Equal(t, 2, replay.MaxFiles)
	assert.False(t, replay.CaptureEvents.Flag)
	assert.False(t, replay.RedactPromptContent)
	assert.Equal(t, 128, replay.MaxPromptChars)

	market := parseMarketplaceOptions(cfg)
	assert.True(t, market.Enabled)
	assert.Equal(t, "https://example.com/index.json", market.IndexURL)
	assert.Equal(t, ".cache/mp", market.CacheDir)
	assert.Equal(t, "rules/community", market.InstallDir)
	assert.Equal(t, 15, market.RefreshIntervalMinutes)
	assert.False(t, market.RequireChecksum)
}

func testContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	t.Cleanup(cancel)
	return ctx
}
