package proxy

import (
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTenancyResolver_DefaultAndFallback(t *testing.T) {
	disableAdaptive := false
	resolver := newTenancyResolver(TenancyOptions{
		Enabled:       true,
		Header:        "X-PIF-Tenant",
		DefaultTenant: "default",
		Tenants: map[string]TenantPolicyOptions{
			"default": {
				Action:    "block",
				Threshold: 0.6,
				RateLimit: RateLimitOptions{RequestsPerMinute: 120, Burst: 30, KeyHeader: "X-Forwarded-For"},
			},
			"team-a": {
				Action:    "flag",
				Threshold: 0.8,
				RateLimit: RateLimitOptions{RequestsPerMinute: 20, Burst: 5},
				AdaptiveThreshold: TenantAdaptiveThresholdOverrideOptions{
					Enabled:      &disableAdaptive,
					MinThreshold: 0.3,
					EWMAAlpha:    0.4,
				},
			},
		},
	}, ActionBlock, 0.5, RateLimitOptions{Enabled: true, RequestsPerMinute: 120, Burst: 30, KeyHeader: "X-Forwarded-For"}, AdaptiveThresholdOptions{Enabled: true, MinThreshold: 0.25, EWMAAlpha: 0.2})

	req := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	req.Header.Set("X-PIF-Tenant", "team-a")
	resolved := resolver.resolve(req)
	assert.Equal(t, "team-a", resolved.Tenant)
	assert.Equal(t, ActionFlag, resolved.Action)
	assert.Equal(t, 0.8, resolved.Threshold)
	assert.Equal(t, 20, resolved.RateLimit.RequestsPerMinute)
	assert.Equal(t, 5, resolved.RateLimit.Burst)
	assert.False(t, resolved.AdaptiveThreshold.Enabled)
	assert.Equal(t, 0.3, resolved.AdaptiveThreshold.MinThreshold)
	assert.Equal(t, 0.4, resolved.AdaptiveThreshold.EWMAAlpha)

	unknownReq := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	unknownReq.Header.Set("X-PIF-Tenant", "unknown")
	unknown := resolver.resolve(unknownReq)
	assert.Equal(t, "default", unknown.Tenant)
	assert.Equal(t, ActionBlock, unknown.Action)
	assert.Equal(t, 0.6, unknown.Threshold)
}

func TestTenancyResolver_ConfiguredTenants(t *testing.T) {
	resolver := newTenancyResolver(TenancyOptions{
		Enabled:       true,
		DefaultTenant: "default",
		Tenants: map[string]TenantPolicyOptions{
			"b": {},
			"a": {},
		},
	}, ActionBlock, 0.5, RateLimitOptions{}, AdaptiveThresholdOptions{})

	tenants := resolver.configuredTenants()
	require.Len(t, tenants, 3)
	assert.Equal(t, []string{"a", "b", "default"}, tenants)
}
