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

// TenantAdaptiveThresholdOverrideOptions defines optional per-tenant adaptive settings.
type TenantAdaptiveThresholdOverrideOptions struct {
	Enabled      *bool
	MinThreshold float64
	EWMAAlpha    float64
}

// TenantPolicyOptions defines per-tenant runtime policy overrides.
type TenantPolicyOptions struct {
	Action            string
	Threshold         float64
	RateLimit         RateLimitOptions
	AdaptiveThreshold TenantAdaptiveThresholdOverrideOptions
}

// TenancyOptions controls tenant identification and per-tenant overrides.
type TenancyOptions struct {
	Enabled       bool
	Header        string
	DefaultTenant string
	Tenants       map[string]TenantPolicyOptions
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
	Name      string                 `json:"name"`
	Version   string                 `json:"version,omitempty"`
	RuleCount int                    `json:"rule_count"`
	Source    string                 `json:"source,omitempty"`
	Path      string                 `json:"path,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
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

// AlertingPagerDutyOptions controls PagerDuty Events API sink behavior.
type AlertingPagerDutyOptions struct {
	Enabled        bool
	URL            string
	RoutingKey     string
	Timeout        time.Duration
	MaxRetries     int
	BackoffInitial time.Duration
	Source         string
	Component      string
	Group          string
	Class          string
}

// AlertingOptions configures real-time alerting pipeline behavior.
type AlertingOptions struct {
	Enabled        bool
	QueueSize      int
	Events         AlertingEventOptions
	ThrottleWindow time.Duration
	Webhook        AlertingSinkOptions
	Slack          AlertingSinkOptions
	PagerDuty      AlertingPagerDutyOptions
}

// AlertingRuntimeOptions contains alerting context needed by middleware.
type AlertingRuntimeOptions struct {
	Enabled        bool
	Events         AlertingEventOptions
	ThrottleWindow time.Duration
	TargetURL      string
}

// ReplayCaptureEventsOptions controls which runtime decisions are persisted.
type ReplayCaptureEventsOptions struct {
	Block     bool
	RateLimit bool
	ScanError bool
	Flag      bool
}

// ReplayOptions configures local replay/forensics capture.
type ReplayOptions struct {
	Enabled             bool
	StoragePath         string
	MaxFileSizeMB       int
	MaxFiles            int
	CaptureEvents       ReplayCaptureEventsOptions
	RedactPromptContent bool
	MaxPromptChars      int
}

// MarketplaceOptions configures community rule marketplace behavior.
type MarketplaceOptions struct {
	Enabled                bool
	IndexURL               string
	CacheDir               string
	InstallDir             string
	RefreshIntervalMinutes int
	RequireChecksum        bool
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
	Tenancy           TenancyOptions
	Alerting          AlertingRuntimeOptions
	AlertPublisher    AlertPublisher
	Replay            ReplayOptions
	ReplayStore       ReplayStore
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
	Tenancy           TenancyOptions
	Metrics           *Metrics
	Dashboard         DashboardOptions
	RuleInventory     []RuleSetInfo
	RuleManager       RuleManager
	Alerting          AlertingOptions
	Replay            ReplayOptions
	ReplayStore       ReplayStore
	Marketplace       MarketplaceOptions
}
