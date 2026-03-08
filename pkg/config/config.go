package config

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

// Config holds all PIF configuration.
type Config struct {
	Detector  DetectorConfig  `mapstructure:"detector"`
	Rules     RulesConfig     `mapstructure:"rules"`
	Proxy     ProxyConfig     `mapstructure:"proxy"`
	Dashboard DashboardConfig `mapstructure:"dashboard"`
	Alerting  AlertingConfig  `mapstructure:"alerting"`
	Webhook   WebhookConfig   `mapstructure:"webhook"`
	Allowlist AllowlistConfig `mapstructure:"allowlist"`
	Logging   LoggingConfig   `mapstructure:"logging"`
}

type DetectorConfig struct {
	Threshold         float64                 `mapstructure:"threshold"`
	MinSeverity       string                  `mapstructure:"min_severity"`
	TimeoutMs         int                     `mapstructure:"timeout_ms"`
	Strategy          string                  `mapstructure:"ensemble_strategy"`
	MLModelPath       string                  `mapstructure:"ml_model_path"`
	MLThreshold       float64                 `mapstructure:"ml_threshold"`
	Weights           WeightsConfig           `mapstructure:"weights"`
	AdaptiveThreshold AdaptiveThresholdConfig `mapstructure:"adaptive_threshold"`
}

// WeightsConfig defines ensemble weights for each detector type.
type WeightsConfig struct {
	Regex float64 `mapstructure:"regex"`
	ML    float64 `mapstructure:"ml"`
}

type RulesConfig struct {
	Paths       []string `mapstructure:"paths"`
	CustomPaths []string `mapstructure:"custom_paths"`
}

type ProxyConfig struct {
	Listen       string          `mapstructure:"listen"`
	Target       string          `mapstructure:"target"`
	Action       string          `mapstructure:"action"`
	MaxBodySize  int64           `mapstructure:"max_body_size"`
	ReadTimeout  string          `mapstructure:"read_timeout"`
	WriteTimeout string          `mapstructure:"write_timeout"`
	RateLimit    RateLimitConfig `mapstructure:"rate_limit"`
}

type RateLimitConfig struct {
	Enabled           bool   `mapstructure:"enabled"`
	RequestsPerMinute int    `mapstructure:"requests_per_minute"`
	Burst             int    `mapstructure:"burst"`
	KeyHeader         string `mapstructure:"key_header"`
}

type AdaptiveThresholdConfig struct {
	Enabled      bool    `mapstructure:"enabled"`
	MinThreshold float64 `mapstructure:"min_threshold"`
	EWMAAlpha    float64 `mapstructure:"ewma_alpha"`
}

type DashboardConfig struct {
	Enabled        bool                          `mapstructure:"enabled"`
	Path           string                        `mapstructure:"path"`
	APIPrefix      string                        `mapstructure:"api_prefix"`
	RefreshSeconds int                           `mapstructure:"refresh_seconds"`
	Auth           DashboardAuthConfig           `mapstructure:"auth"`
	RuleManagement DashboardRuleManagementConfig `mapstructure:"rule_management"`
}

type DashboardAuthConfig struct {
	Enabled  bool   `mapstructure:"enabled"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
}

type DashboardRuleManagementConfig struct {
	Enabled bool `mapstructure:"enabled"`
}

type AlertingConfig struct {
	Enabled   bool                   `mapstructure:"enabled"`
	QueueSize int                    `mapstructure:"queue_size"`
	Events    AlertingEventsConfig   `mapstructure:"events"`
	Throttle  AlertingThrottleConfig `mapstructure:"throttle"`
	Webhook   AlertingSinkConfig     `mapstructure:"webhook"`
	Slack     AlertingSinkConfig     `mapstructure:"slack"`
}

type AlertingEventsConfig struct {
	Block     bool `mapstructure:"block"`
	RateLimit bool `mapstructure:"rate_limit"`
	ScanError bool `mapstructure:"scan_error"`
}

type AlertingThrottleConfig struct {
	WindowSeconds int `mapstructure:"window_seconds"`
}

type AlertingSinkConfig struct {
	Enabled            bool   `mapstructure:"enabled"`
	URL                string `mapstructure:"url"`
	IncomingWebhookURL string `mapstructure:"incoming_webhook_url"`
	Timeout            string `mapstructure:"timeout"`
	MaxRetries         int    `mapstructure:"max_retries"`
	BackoffInitialMs   int    `mapstructure:"backoff_initial_ms"`
	AuthBearerToken    string `mapstructure:"auth_bearer_token"`
}

type WebhookConfig struct {
	Listen         string `mapstructure:"listen"`
	TLSCertFile    string `mapstructure:"tls_cert_file"`
	TLSKeyFile     string `mapstructure:"tls_key_file"`
	PIFHostPattern string `mapstructure:"pif_host_pattern"`
}

type AllowlistConfig struct {
	Patterns []string `mapstructure:"patterns"`
	Hashes   []string `mapstructure:"hashes"`
}

type LoggingConfig struct {
	Level      string `mapstructure:"level"`
	Format     string `mapstructure:"format"`
	Output     string `mapstructure:"output"`
	LogPrompts bool   `mapstructure:"log_prompts"`
}

// Default returns a Config with sensible defaults.
func Default() *Config {
	return &Config{
		Detector: DetectorConfig{
			Threshold:   0.5,
			MinSeverity: "low",
			TimeoutMs:   100,
			Strategy:    "weighted",
			MLModelPath: "",
			MLThreshold: 0.85,
			Weights: WeightsConfig{
				Regex: 0.6,
				ML:    0.4,
			},
			AdaptiveThreshold: AdaptiveThresholdConfig{
				Enabled:      true,
				MinThreshold: 0.25,
				EWMAAlpha:    0.2,
			},
		},
		Rules: RulesConfig{
			Paths: []string{
				"rules/owasp-llm-top10.yaml",
				"rules/jailbreak-patterns.yaml",
				"rules/data-exfil.yaml",
			},
		},
		Proxy: ProxyConfig{
			Listen:       ":8080",
			Target:       "https://api.openai.com",
			Action:       "block",
			MaxBodySize:  1048576, // 1MB
			ReadTimeout:  "10s",
			WriteTimeout: "30s",
			RateLimit: RateLimitConfig{
				Enabled:           true,
				RequestsPerMinute: 120,
				Burst:             30,
				KeyHeader:         "X-Forwarded-For",
			},
		},
		Dashboard: DashboardConfig{
			Enabled:        false,
			Path:           "/dashboard",
			APIPrefix:      "/api/dashboard",
			RefreshSeconds: 5,
			Auth: DashboardAuthConfig{
				Enabled:  false,
				Username: "",
				Password: "",
			},
			RuleManagement: DashboardRuleManagementConfig{
				Enabled: false,
			},
		},
		Alerting: AlertingConfig{
			Enabled:   false,
			QueueSize: 1024,
			Events: AlertingEventsConfig{
				Block:     true,
				RateLimit: true,
				ScanError: true,
			},
			Throttle: AlertingThrottleConfig{
				WindowSeconds: 60,
			},
			Webhook: AlertingSinkConfig{
				Enabled:          false,
				URL:              "",
				Timeout:          "3s",
				MaxRetries:       3,
				BackoffInitialMs: 200,
				AuthBearerToken:  "",
			},
			Slack: AlertingSinkConfig{
				Enabled:            false,
				IncomingWebhookURL: "",
				Timeout:            "3s",
				MaxRetries:         3,
				BackoffInitialMs:   200,
			},
		},
		Webhook: WebhookConfig{
			Listen:         ":8443",
			TLSCertFile:    "/etc/pif/webhook/tls.crt",
			TLSKeyFile:     "/etc/pif/webhook/tls.key",
			PIFHostPattern: `(?i)pif-proxy`,
		},
		Logging: LoggingConfig{
			Level:      "info",
			Format:     "json",
			Output:     "stderr",
			LogPrompts: false,
		},
	}
}

// Load reads configuration from the given file path, environment variables,
// and applies defaults.
func Load(path string) (*Config, error) {
	v := viper.New()

	// Set defaults
	defaults := Default()
	v.SetDefault("detector.threshold", defaults.Detector.Threshold)
	v.SetDefault("detector.min_severity", defaults.Detector.MinSeverity)
	v.SetDefault("detector.timeout_ms", defaults.Detector.TimeoutMs)
	v.SetDefault("detector.ensemble_strategy", defaults.Detector.Strategy)
	v.SetDefault("detector.ml_model_path", defaults.Detector.MLModelPath)
	v.SetDefault("detector.ml_threshold", defaults.Detector.MLThreshold)
	v.SetDefault("detector.weights.regex", defaults.Detector.Weights.Regex)
	v.SetDefault("detector.weights.ml", defaults.Detector.Weights.ML)
	v.SetDefault("detector.adaptive_threshold.enabled", defaults.Detector.AdaptiveThreshold.Enabled)
	v.SetDefault("detector.adaptive_threshold.min_threshold", defaults.Detector.AdaptiveThreshold.MinThreshold)
	v.SetDefault("detector.adaptive_threshold.ewma_alpha", defaults.Detector.AdaptiveThreshold.EWMAAlpha)
	v.SetDefault("rules.paths", defaults.Rules.Paths)
	v.SetDefault("proxy.listen", defaults.Proxy.Listen)
	v.SetDefault("proxy.target", defaults.Proxy.Target)
	v.SetDefault("proxy.action", defaults.Proxy.Action)
	v.SetDefault("proxy.max_body_size", defaults.Proxy.MaxBodySize)
	v.SetDefault("proxy.read_timeout", defaults.Proxy.ReadTimeout)
	v.SetDefault("proxy.write_timeout", defaults.Proxy.WriteTimeout)
	v.SetDefault("proxy.rate_limit.enabled", defaults.Proxy.RateLimit.Enabled)
	v.SetDefault("proxy.rate_limit.requests_per_minute", defaults.Proxy.RateLimit.RequestsPerMinute)
	v.SetDefault("proxy.rate_limit.burst", defaults.Proxy.RateLimit.Burst)
	v.SetDefault("proxy.rate_limit.key_header", defaults.Proxy.RateLimit.KeyHeader)
	v.SetDefault("dashboard.enabled", defaults.Dashboard.Enabled)
	v.SetDefault("dashboard.path", defaults.Dashboard.Path)
	v.SetDefault("dashboard.api_prefix", defaults.Dashboard.APIPrefix)
	v.SetDefault("dashboard.refresh_seconds", defaults.Dashboard.RefreshSeconds)
	v.SetDefault("dashboard.auth.enabled", defaults.Dashboard.Auth.Enabled)
	v.SetDefault("dashboard.auth.username", defaults.Dashboard.Auth.Username)
	v.SetDefault("dashboard.auth.password", defaults.Dashboard.Auth.Password)
	v.SetDefault("dashboard.rule_management.enabled", defaults.Dashboard.RuleManagement.Enabled)
	v.SetDefault("alerting.enabled", defaults.Alerting.Enabled)
	v.SetDefault("alerting.queue_size", defaults.Alerting.QueueSize)
	v.SetDefault("alerting.events.block", defaults.Alerting.Events.Block)
	v.SetDefault("alerting.events.rate_limit", defaults.Alerting.Events.RateLimit)
	v.SetDefault("alerting.events.scan_error", defaults.Alerting.Events.ScanError)
	v.SetDefault("alerting.throttle.window_seconds", defaults.Alerting.Throttle.WindowSeconds)
	v.SetDefault("alerting.webhook.enabled", defaults.Alerting.Webhook.Enabled)
	v.SetDefault("alerting.webhook.url", defaults.Alerting.Webhook.URL)
	v.SetDefault("alerting.webhook.timeout", defaults.Alerting.Webhook.Timeout)
	v.SetDefault("alerting.webhook.max_retries", defaults.Alerting.Webhook.MaxRetries)
	v.SetDefault("alerting.webhook.backoff_initial_ms", defaults.Alerting.Webhook.BackoffInitialMs)
	v.SetDefault("alerting.webhook.auth_bearer_token", defaults.Alerting.Webhook.AuthBearerToken)
	v.SetDefault("alerting.slack.enabled", defaults.Alerting.Slack.Enabled)
	v.SetDefault("alerting.slack.incoming_webhook_url", defaults.Alerting.Slack.IncomingWebhookURL)
	v.SetDefault("alerting.slack.timeout", defaults.Alerting.Slack.Timeout)
	v.SetDefault("alerting.slack.max_retries", defaults.Alerting.Slack.MaxRetries)
	v.SetDefault("alerting.slack.backoff_initial_ms", defaults.Alerting.Slack.BackoffInitialMs)
	v.SetDefault("webhook.listen", defaults.Webhook.Listen)
	v.SetDefault("webhook.tls_cert_file", defaults.Webhook.TLSCertFile)
	v.SetDefault("webhook.tls_key_file", defaults.Webhook.TLSKeyFile)
	v.SetDefault("webhook.pif_host_pattern", defaults.Webhook.PIFHostPattern)
	v.SetDefault("logging.level", defaults.Logging.Level)
	v.SetDefault("logging.format", defaults.Logging.Format)
	v.SetDefault("logging.output", defaults.Logging.Output)
	v.SetDefault("logging.log_prompts", defaults.Logging.LogPrompts)

	// Environment variables: PIF_DETECTOR_THRESHOLD, PIF_PROXY_LISTEN, etc.
	v.SetEnvPrefix("PIF")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	// Read config file if provided
	if path != "" {
		v.SetConfigFile(path)
		if err := v.ReadInConfig(); err != nil {
			return nil, fmt.Errorf("reading config file: %w", err)
		}
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	return &cfg, nil
}
