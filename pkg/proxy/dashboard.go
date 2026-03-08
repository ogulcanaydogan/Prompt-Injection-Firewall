package proxy

import (
	"context"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ogulcanaydogan/Prompt-Injection-Firewall/pkg/detector"
	"github.com/ogulcanaydogan/Prompt-Injection-Firewall/pkg/rules"
)

//go:embed dashboard/*
var dashboardFS embed.FS

var (
	dashboardIndexHTML = mustReadDashboardAsset("dashboard/index.html")
	dashboardAppJS     = mustReadDashboardAsset("dashboard/app.js")
	dashboardStylesCSS = mustReadDashboardAsset("dashboard/styles.css")
)

type dashboardTotals struct {
	Requests      uint64 `json:"requests"`
	Injections    uint64 `json:"injections"`
	RateLimit     uint64 `json:"rate_limit_events"`
	RuleSetCount  int    `json:"rule_set_count"`
	LoadedRuleCnt int    `json:"loaded_rule_count"`
}

type dashboardConfigPublic struct {
	Listen            string                   `json:"listen"`
	TargetURL         string                   `json:"target_url"`
	Action            string                   `json:"action"`
	Threshold         float64                  `json:"threshold"`
	RateLimit         RateLimitOptions         `json:"rate_limit"`
	AdaptiveThreshold AdaptiveThresholdOptions `json:"adaptive_threshold"`
	Dashboard         struct {
		Path                  string `json:"path"`
		APIPrefix             string `json:"api_prefix"`
		RefreshSeconds        int    `json:"refresh_seconds"`
		AuthEnabled           bool   `json:"auth_enabled"`
		RuleManagementEnabled bool   `json:"rule_management_enabled"`
	} `json:"dashboard"`
}

type dashboardSummaryResponse struct {
	UptimeSeconds          int64                            `json:"uptime_seconds"`
	LastUpdated            time.Time                        `json:"last_updated"`
	P95ScanDurationSeconds float64                          `json:"p95_scan_duration_seconds"`
	Totals                 dashboardTotals                  `json:"totals"`
	Tenants                map[string]dashboardTenantTotals `json:"tenants,omitempty"`
	Config                 dashboardConfigPublic            `json:"config"`
}

type dashboardTenantTotals struct {
	Requests   uint64 `json:"requests"`
	Injections uint64 `json:"injections"`
	RateLimit  uint64 `json:"rate_limit_events"`
}

type dashboardRuleManagementStatus struct {
	Enabled     bool   `json:"enabled"`
	Writable    bool   `json:"writable"`
	ManagedPath string `json:"managed_path,omitempty"`
}

type dashboardRulesResponse struct {
	RuleSets       []RuleSetInfo                 `json:"rule_sets"`
	TotalRuleSets  int                           `json:"total_rule_sets"`
	TotalRules     int                           `json:"total_rules"`
	ManagedRules   []rules.Rule                  `json:"managed_rules"`
	RuleManagement dashboardRuleManagementStatus `json:"rule_management"`
}

type dashboardRuleMutationRequest struct {
	Rule rules.Rule `json:"rule"`
}

type dashboardReplayListResponse struct {
	Events []ReplayEventRecord `json:"events"`
	Total  int                 `json:"total"`
}

func registerDashboardNotFoundRoutes(mux *http.ServeMux, path, apiPrefix string) {
	dashboardPath := normalizeURLPath(path, "/dashboard")
	dashboardAPI := normalizeURLPath(apiPrefix, "/api/dashboard")
	notFound := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	mux.Handle(dashboardPath, notFound)
	mux.Handle(dashboardPath+"/", notFound)
	mux.Handle(dashboardAPI, notFound)
	mux.Handle(dashboardAPI+"/", notFound)
}

func registerDashboardRoutes(mux *http.ServeMux, opts ServerOptions) {
	dashboardPath := normalizeURLPath(opts.Dashboard.Path, "/dashboard")
	dashboardAPI := normalizeURLPath(opts.Dashboard.APIPrefix, "/api/dashboard")
	rulesBase := dashboardAPI + "/rules"
	replaysBase := dashboardAPI + "/replays"
	refreshSeconds := opts.Dashboard.RefreshSeconds
	if refreshSeconds <= 0 {
		refreshSeconds = 5
	}

	authMiddleware := newDashboardAuthMiddleware(opts.Dashboard.Auth)

	indexHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Path != dashboardPath && r.URL.Path != dashboardPath+"/" {
			http.NotFound(w, r)
			return
		}
		html := strings.ReplaceAll(string(dashboardIndexHTML), "__API_PREFIX__", dashboardAPI)
		html = strings.ReplaceAll(html, "__REFRESH_SECONDS__", strconv.Itoa(refreshSeconds))
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(html))
	})

	jsHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		_, _ = w.Write(dashboardAppJS)
	})

	cssHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		_, _ = w.Write(dashboardStylesCSS)
	})

	summaryHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		snapshot := opts.Metrics.Snapshot()
		rulesSnapshot := snapshotRules(opts)

		response := dashboardSummaryResponse{
			UptimeSeconds:          snapshot.UptimeSeconds,
			LastUpdated:            snapshot.LastUpdate,
			P95ScanDurationSeconds: snapshot.ScanDurationSeconds.P95,
			Totals: dashboardTotals{
				Requests:      snapshot.TotalRequests,
				Injections:    snapshot.TotalInjectionDetections,
				RateLimit:     snapshot.TotalRateLimitEvents,
				RuleSetCount:  rulesSnapshot.TotalRuleSets,
				LoadedRuleCnt: rulesSnapshot.TotalRules,
			},
			Tenants: tenantBreakdownForDashboard(opts, snapshot),
			Config: dashboardConfigPublic{
				Listen:            opts.Listen,
				TargetURL:         opts.TargetURL,
				Action:            opts.Action,
				Threshold:         opts.Threshold,
				RateLimit:         opts.RateLimit,
				AdaptiveThreshold: opts.AdaptiveThreshold,
			},
		}
		response.Config.Dashboard.Path = dashboardPath
		response.Config.Dashboard.APIPrefix = dashboardAPI
		response.Config.Dashboard.RefreshSeconds = refreshSeconds
		response.Config.Dashboard.AuthEnabled = opts.Dashboard.Auth.Enabled
		response.Config.Dashboard.RuleManagementEnabled = opts.Dashboard.RuleManagementEnabled

		writeDashboardJSON(w, response)
	})

	metricsHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		snapshot := opts.Metrics.Snapshot()
		snapshot.TenantBreakdown = filterTenantBreakdown(opts, snapshot.TenantBreakdown)
		writeDashboardJSON(w, snapshot)
	})

	rulesHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			writeDashboardJSON(w, snapshotRules(opts))
			return
		case http.MethodPost:
			if !allowDashboardRuleWrite(w, r, opts) {
				return
			}
			req, err := decodeDashboardRuleMutation(r.Body)
			if err != nil {
				http.Error(w, fmt.Sprintf("invalid payload: %v", err), http.StatusBadRequest)
				return
			}
			if err := opts.RuleManager.CreateRule(req.Rule); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			writeDashboardJSONStatus(w, http.StatusCreated, snapshotRules(opts))
			return
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	rulesItemHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, rulesBase+"/")
		if id == "" || strings.Contains(id, "/") {
			http.NotFound(w, r)
			return
		}

		switch r.Method {
		case http.MethodPut:
			if !allowDashboardRuleWrite(w, r, opts) {
				return
			}
			req, err := decodeDashboardRuleMutation(r.Body)
			if err != nil {
				http.Error(w, fmt.Sprintf("invalid payload: %v", err), http.StatusBadRequest)
				return
			}
			if err := opts.RuleManager.UpdateRule(id, req.Rule); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			writeDashboardJSON(w, snapshotRules(opts))
		case http.MethodDelete:
			if !allowDashboardRuleWrite(w, r, opts) {
				return
			}
			if err := opts.RuleManager.DeleteRule(id); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			writeDashboardJSON(w, snapshotRules(opts))
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	apiNotFoundHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})

	replaysHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !allowDashboardReplayRead(w, r, opts) {
			return
		}
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		limit, _ := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("limit")))
		eventType := ReplayEventType(strings.TrimSpace(r.URL.Query().Get("event_type")))
		events, err := opts.ReplayStore.List(ReplayListFilter{
			Tenant:    strings.TrimSpace(r.URL.Query().Get("tenant")),
			EventType: eventType,
			Limit:     limit,
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeDashboardJSON(w, dashboardReplayListResponse{
			Events: events,
			Total:  len(events),
		})
	})

	replayItemHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !allowDashboardReplayRead(w, r, opts) {
			return
		}

		suffix := strings.TrimPrefix(r.URL.Path, replaysBase+"/")
		if suffix == "" || suffix == r.URL.Path {
			http.NotFound(w, r)
			return
		}

		if strings.HasSuffix(suffix, "/rescan") {
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			id := strings.TrimSuffix(suffix, "/rescan")
			if id == "" || strings.Contains(id, "/") {
				http.NotFound(w, r)
				return
			}
			d := dashboardDetector(opts)
			if d == nil {
				http.Error(w, "detector unavailable", http.StatusServiceUnavailable)
				return
			}
			timeout := 5 * time.Second
			if opts.ScanTimeout > 0 {
				timeout = opts.ScanTimeout
			}
			ctx, cancel := context.WithTimeout(r.Context(), timeout)
			defer cancel()

			rescan, err := opts.ReplayStore.Rescan(ctx, id, d)
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					http.NotFound(w, r)
					return
				}
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			writeDashboardJSON(w, rescan)
			return
		}

		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if strings.Contains(suffix, "/") {
			http.NotFound(w, r)
			return
		}
		event, err := opts.ReplayStore.Get(suffix)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				http.NotFound(w, r)
				return
			}
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeDashboardJSON(w, event)
	})

	mux.Handle(dashboardPath, authMiddleware(indexHandler))
	mux.Handle(dashboardPath+"/", authMiddleware(indexHandler))
	mux.Handle(dashboardPath+"/app.js", authMiddleware(jsHandler))
	mux.Handle(dashboardPath+"/styles.css", authMiddleware(cssHandler))
	mux.Handle(dashboardAPI, authMiddleware(apiNotFoundHandler))
	mux.Handle(dashboardAPI+"/", authMiddleware(apiNotFoundHandler))
	mux.Handle(dashboardAPI+"/summary", authMiddleware(summaryHandler))
	mux.Handle(dashboardAPI+"/metrics", authMiddleware(metricsHandler))
	mux.Handle(rulesBase, authMiddleware(rulesHandler))
	mux.Handle(rulesBase+"/", authMiddleware(rulesItemHandler))
	mux.Handle(replaysBase, authMiddleware(replaysHandler))
	mux.Handle(replaysBase+"/", authMiddleware(replayItemHandler))
}

func allowDashboardRuleWrite(w http.ResponseWriter, r *http.Request, opts ServerOptions) bool {
	if !opts.Dashboard.RuleManagementEnabled {
		http.NotFound(w, r)
		return false
	}
	if opts.RuleManager == nil {
		http.Error(w, "rule manager unavailable", http.StatusServiceUnavailable)
		return false
	}
	if !opts.Dashboard.Auth.Enabled {
		http.Error(w, "rule management requires dashboard auth", http.StatusForbidden)
		return false
	}
	return true
}

func snapshotRules(opts ServerOptions) dashboardRulesResponse {
	if opts.RuleManager != nil {
		snapshot := opts.RuleManager.Snapshot()
		return dashboardRulesResponse{
			RuleSets:      snapshot.RuleSets,
			TotalRuleSets: snapshot.TotalRuleSets,
			TotalRules:    snapshot.TotalRules,
			ManagedRules:  snapshot.ManagedRules,
			RuleManagement: dashboardRuleManagementStatus{
				Enabled:     opts.Dashboard.RuleManagementEnabled,
				Writable:    opts.Dashboard.RuleManagementEnabled && opts.Dashboard.Auth.Enabled,
				ManagedPath: snapshot.ManagedPath,
			},
		}
	}

	totalRules := 0
	for _, rs := range opts.RuleInventory {
		totalRules += rs.RuleCount
	}
	rulesets := opts.RuleInventory
	if rulesets == nil {
		rulesets = make([]RuleSetInfo, 0)
	}
	return dashboardRulesResponse{
		RuleSets:      rulesets,
		TotalRuleSets: len(rulesets),
		TotalRules:    totalRules,
		ManagedRules:  []rules.Rule{},
		RuleManagement: dashboardRuleManagementStatus{
			Enabled:  opts.Dashboard.RuleManagementEnabled,
			Writable: opts.Dashboard.RuleManagementEnabled && opts.Dashboard.Auth.Enabled,
		},
	}
}

func decodeDashboardRuleMutation(body io.Reader) (*dashboardRuleMutationRequest, error) {
	dec := json.NewDecoder(body)
	dec.DisallowUnknownFields()
	var req dashboardRuleMutationRequest
	if err := dec.Decode(&req); err != nil {
		return nil, err
	}
	return &req, nil
}

func allowDashboardReplayRead(w http.ResponseWriter, r *http.Request, opts ServerOptions) bool {
	if !opts.Replay.Enabled || opts.ReplayStore == nil || !opts.ReplayStore.Enabled() {
		http.NotFound(w, r)
		return false
	}
	return true
}

func dashboardDetector(opts ServerOptions) detector.Detector {
	if opts.RuleManager != nil {
		if d := opts.RuleManager.CurrentDetector(); d != nil {
			return d
		}
		return opts.RuleManager.Detector()
	}
	return nil
}

func tenantBreakdownForDashboard(opts ServerOptions, snapshot MetricsSnapshot) map[string]dashboardTenantTotals {
	if len(snapshot.TenantBreakdown) == 0 && (!opts.Tenancy.Enabled || len(opts.Tenancy.Tenants) == 0) {
		return nil
	}

	out := make(map[string]dashboardTenantTotals)
	if opts.Tenancy.Enabled {
		defaultTenant := strings.TrimSpace(opts.Tenancy.DefaultTenant)
		if defaultTenant == "" {
			defaultTenant = "default"
		}
		out[defaultTenant] = dashboardTenantTotals{}
		for tenant := range opts.Tenancy.Tenants {
			trimmed := strings.TrimSpace(tenant)
			if trimmed == "" {
				continue
			}
			out[trimmed] = dashboardTenantTotals{}
		}
	}
	for tenant, values := range snapshot.TenantBreakdown {
		if _, ok := out[tenant]; !ok && opts.Tenancy.Enabled {
			continue
		}
		out[tenant] = dashboardTenantTotals{
			Requests:   values.TotalRequests,
			Injections: values.TotalInjectionDetections,
			RateLimit:  values.TotalRateLimitEvents,
		}
	}
	return out
}

func filterTenantBreakdown(opts ServerOptions, snapshot map[string]TenantMetricsSnapshot) map[string]TenantMetricsSnapshot {
	if !opts.Tenancy.Enabled {
		return snapshot
	}
	if len(snapshot) == 0 {
		return map[string]TenantMetricsSnapshot{}
	}

	allowed := make(map[string]struct{}, len(opts.Tenancy.Tenants)+1)
	defaultTenant := strings.TrimSpace(opts.Tenancy.DefaultTenant)
	if defaultTenant == "" {
		defaultTenant = "default"
	}
	allowed[defaultTenant] = struct{}{}
	for tenant := range opts.Tenancy.Tenants {
		trimmed := strings.TrimSpace(tenant)
		if trimmed == "" {
			continue
		}
		allowed[trimmed] = struct{}{}
	}

	filtered := make(map[string]TenantMetricsSnapshot)
	for tenant, values := range snapshot {
		if _, ok := allowed[tenant]; !ok {
			continue
		}
		filtered[tenant] = values
	}
	return filtered
}

func newDashboardAuthMiddleware(auth DashboardAuthOptions) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if !auth.Enabled {
			return next
		}

		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if auth.Username == "" || auth.Password == "" {
				http.Error(w, "dashboard auth misconfigured", http.StatusServiceUnavailable)
				return
			}

			username, password, ok := r.BasicAuth()
			if !ok || !secureEqual(username, auth.Username) || !secureEqual(password, auth.Password) {
				w.Header().Set("WWW-Authenticate", `Basic realm="pif-dashboard"`)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func writeDashboardJSON(w http.ResponseWriter, payload interface{}) {
	writeDashboardJSONStatus(w, http.StatusOK, payload)
}

func writeDashboardJSONStatus(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		http.Error(w, "encoding response", http.StatusInternalServerError)
	}
}

func normalizeURLPath(path, fallback string) string {
	if path == "" {
		path = fallback
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if path != "/" {
		path = strings.TrimSuffix(path, "/")
	}
	return path
}

func mustReadDashboardAsset(name string) []byte {
	data, err := dashboardFS.ReadFile(name)
	if err != nil {
		panic(err)
	}
	return data
}

func secureEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
