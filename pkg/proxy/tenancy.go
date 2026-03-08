package proxy

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
)

type resolvedTenantPolicy struct {
	Tenant            string
	Action            Action
	Threshold         float64
	RateLimit         RateLimitOptions
	AdaptiveThreshold AdaptiveThresholdOptions
}

type tenancyResolver struct {
	enabled        bool
	header         string
	defaultTenant  string
	tenantPolicies map[string]TenantPolicyOptions
	global         resolvedTenantPolicy
}

func newTenancyResolver(opts TenancyOptions, globalAction Action, globalThreshold float64, globalRate RateLimitOptions, globalAdaptive AdaptiveThresholdOptions) *tenancyResolver {
	header := strings.TrimSpace(opts.Header)
	if header == "" {
		header = "X-PIF-Tenant"
	}
	defaultTenant := strings.TrimSpace(opts.DefaultTenant)
	if defaultTenant == "" {
		defaultTenant = "default"
	}
	global := resolvedTenantPolicy{
		Tenant:            defaultTenant,
		Action:            globalAction,
		Threshold:         globalThreshold,
		RateLimit:         globalRate,
		AdaptiveThreshold: globalAdaptive,
	}
	copyPolicies := make(map[string]TenantPolicyOptions, len(opts.Tenants))
	for name, policy := range opts.Tenants {
		trimmed := strings.TrimSpace(name)
		if trimmed == "" {
			continue
		}
		copyPolicies[trimmed] = policy
	}
	return &tenancyResolver{
		enabled:        opts.Enabled,
		header:         header,
		defaultTenant:  defaultTenant,
		tenantPolicies: copyPolicies,
		global:         global,
	}
}

func (r *tenancyResolver) resolve(req *http.Request) resolvedTenantPolicy {
	if r == nil {
		return resolvedTenantPolicy{}
	}
	resolved := r.global

	tenant := r.defaultTenant
	if r.enabled && req != nil {
		headerValue := strings.TrimSpace(req.Header.Get(r.header))
		if headerValue != "" {
			tenant = headerValue
		}
	}

	policy, ok := r.tenantPolicies[tenant]
	if !ok {
		if fallback, hasFallback := r.tenantPolicies[r.defaultTenant]; hasFallback {
			policy = fallback
			tenant = r.defaultTenant
			ok = true
		}
	}

	if !r.enabled {
		tenant = r.defaultTenant
	}

	resolved.Tenant = tenant
	if !ok {
		return resolved
	}

	if action := strings.TrimSpace(policy.Action); action != "" {
		resolved.Action = ParseAction(action)
	}
	if policy.Threshold > 0 {
		resolved.Threshold = policy.Threshold
	}

	resolved.RateLimit = mergeTenantRateLimit(resolved.RateLimit, policy.RateLimit)
	resolved.AdaptiveThreshold = mergeTenantAdaptiveThreshold(resolved.AdaptiveThreshold, policy.AdaptiveThreshold)

	return resolved
}

func mergeTenantRateLimit(global RateLimitOptions, policy RateLimitOptions) RateLimitOptions {
	merged := global
	if policy.RequestsPerMinute > 0 {
		merged.Enabled = true
		merged.RequestsPerMinute = policy.RequestsPerMinute
	}
	if policy.Burst > 0 {
		merged.Enabled = true
		merged.Burst = policy.Burst
	}
	if strings.TrimSpace(policy.KeyHeader) != "" {
		merged.KeyHeader = policy.KeyHeader
	}
	return merged
}

func mergeTenantAdaptiveThreshold(global AdaptiveThresholdOptions, policy TenantAdaptiveThresholdOverrideOptions) AdaptiveThresholdOptions {
	merged := global
	explicit := policy.Enabled != nil
	if policy.Enabled != nil {
		merged.Enabled = *policy.Enabled
	}
	if !explicit && (policy.MinThreshold > 0 || policy.EWMAAlpha > 0) {
		merged.Enabled = true
	}
	if policy.MinThreshold > 0 {
		merged.MinThreshold = policy.MinThreshold
	}
	if policy.EWMAAlpha > 0 {
		merged.EWMAAlpha = policy.EWMAAlpha
	}
	return merged
}

func (r *tenancyResolver) configuredTenants() []string {
	if r == nil {
		return nil
	}
	seen := make(map[string]struct{}, len(r.tenantPolicies)+1)
	if r.defaultTenant != "" {
		seen[r.defaultTenant] = struct{}{}
	}
	for name := range r.tenantPolicies {
		seen[name] = struct{}{}
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

type tenantRateLimiterStore struct {
	mu       sync.Mutex
	limiters map[string]*perClientRateLimiter
}

func newTenantRateLimiterStore() *tenantRateLimiterStore {
	return &tenantRateLimiterStore{limiters: make(map[string]*perClientRateLimiter)}
}

func (s *tenantRateLimiterStore) allow(tenant, clientKey string, opts RateLimitOptions) bool {
	if s == nil {
		return true
	}
	key := fmt.Sprintf("%s|%d|%d|%s", tenant, opts.RequestsPerMinute, opts.Burst, strings.ToLower(strings.TrimSpace(opts.KeyHeader)))

	s.mu.Lock()
	limiter, ok := s.limiters[key]
	if !ok {
		limiter = newPerClientRateLimiter(opts)
		s.limiters[key] = limiter
	}
	s.mu.Unlock()

	return limiter.allow(clientKey)
}

type tenantAdaptiveStore struct {
	mu     sync.Mutex
	states map[string]*adaptiveThresholdState
}

func newTenantAdaptiveStore() *tenantAdaptiveStore {
	return &tenantAdaptiveStore{states: make(map[string]*adaptiveThresholdState)}
}

func (s *tenantAdaptiveStore) effectiveThreshold(tenant, clientKey string, base float64, opts AdaptiveThresholdOptions) float64 {
	if s == nil {
		return base
	}
	state := s.getOrCreate(tenant, opts)
	if state == nil {
		return base
	}
	return state.effectiveThreshold(clientKey, base)
}

func (s *tenantAdaptiveStore) update(tenant, clientKey string, isInjection bool, opts AdaptiveThresholdOptions) {
	if s == nil {
		return
	}
	state := s.getOrCreate(tenant, opts)
	if state == nil {
		return
	}
	state.update(clientKey, isInjection)
}

func (s *tenantAdaptiveStore) getOrCreate(tenant string, opts AdaptiveThresholdOptions) *adaptiveThresholdState {
	if !opts.Enabled {
		return nil
	}
	key := fmt.Sprintf("%s|%.4f|%.4f", tenant, opts.MinThreshold, opts.EWMAAlpha)

	s.mu.Lock()
	defer s.mu.Unlock()
	if st, ok := s.states[key]; ok {
		return st
	}
	st := newAdaptiveThresholdState(opts)
	s.states[key] = st
	return st
}
