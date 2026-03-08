package proxy

import (
	"log/slog"
	"time"
)

const (
	defaultMaxBodySize = 1 << 20 // 1MB
	defaultScanTimeout = 50 * time.Millisecond
)

// RateLimitOptions configures per-client rate limiting.
type RateLimitOptions struct {
	Enabled           bool
	RequestsPerMinute int
	Burst             int
	KeyHeader         string
}

// AdaptiveThresholdOptions configures per-client adaptive thresholding.
type AdaptiveThresholdOptions struct {
	Enabled      bool
	MinThreshold float64
	EWMAAlpha    float64
}

// DashboardAuthOptions configures dashboard Basic Auth.
type DashboardAuthOptions struct {
	Enabled  bool
	Username string
	Password string
}

// DashboardOptions configures embedded dashboard behavior.
type DashboardOptions struct {
	Enabled               bool
	Path                  string
	APIPrefix             string
	RefreshSeconds        int
	Auth                  DashboardAuthOptions
	RuleManagementEnabled bool
}

// RuleSetInfo represents dashboard-facing rule inventory metadata.
type RuleSetInfo struct {
	Name      string `json:"name"`
	Version   string `json:"version,omitempty"`
	RuleCount int    `json:"rule_count"`
}

// AlertingEventOptions controls which events produce alerts.
type AlertingEventOptions struct {
	Block     bool
	RateLimit bool
	ScanError bool
}

// AlertingSinkOptions controls outbound sink behavior.
type AlertingSinkOptions struct {
	Enabled         bool
	URL             string
	Timeout         time.Duration
	MaxRetries      int
	BackoffInitial  time.Duration
	AuthBearerToken string
}

// AlertingOptions configures real-time alerting pipeline behavior.
type AlertingOptions struct {
	Enabled        bool
	QueueSize      int
	Events         AlertingEventOptions
	ThrottleWindow time.Duration
	Webhook        AlertingSinkOptions
	Slack          AlertingSinkOptions
}

// AlertingRuntimeOptions contains alerting context needed by middleware.
type AlertingRuntimeOptions struct {
	Enabled        bool
	Events         AlertingEventOptions
	ThrottleWindow time.Duration
	TargetURL      string
}

// MiddlewareOptions configures scanning middleware behavior.
type MiddlewareOptions struct {
	Threshold         float64
	MaxBodySize       int64
	ScanTimeout       time.Duration
	Logger            *slog.Logger
	Metrics           *Metrics
	RateLimit         RateLimitOptions
	AdaptiveThreshold AdaptiveThresholdOptions
	Alerting          AlertingRuntimeOptions
	AlertPublisher    AlertPublisher
}

// ServerOptions configures proxy server behavior.
type ServerOptions struct {
	TargetURL         string
	Listen            string
	Action            string
	Threshold         float64
	MaxBodySize       int64
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	ScanTimeout       time.Duration
	RateLimit         RateLimitOptions
	AdaptiveThreshold AdaptiveThresholdOptions
	Metrics           *Metrics
	Dashboard         DashboardOptions
	RuleInventory     []RuleSetInfo
	RuleManager       RuleManager
	Alerting          AlertingOptions
}
