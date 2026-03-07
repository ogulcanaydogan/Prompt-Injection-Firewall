package proxy

import (
	"crypto/subtle"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

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
	UptimeSeconds          int64                 `json:"uptime_seconds"`
	LastUpdated            time.Time             `json:"last_updated"`
	P95ScanDurationSeconds float64               `json:"p95_scan_duration_seconds"`
	Totals                 dashboardTotals       `json:"totals"`
	Config                 dashboardConfigPublic `json:"config"`
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
		writeDashboardJSON(w, opts.Metrics.Snapshot())
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
