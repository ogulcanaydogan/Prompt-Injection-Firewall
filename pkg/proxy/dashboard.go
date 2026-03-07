package proxy

import (
	"crypto/subtle"
	"embed"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"
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
		Path           string `json:"path"`
		APIPrefix      string `json:"api_prefix"`
		RefreshSeconds int    `json:"refresh_seconds"`
		AuthEnabled    bool   `json:"auth_enabled"`
	} `json:"dashboard"`
}

type dashboardSummaryResponse struct {
	UptimeSeconds          int64                 `json:"uptime_seconds"`
	LastUpdated            time.Time             `json:"last_updated"`
	P95ScanDurationSeconds float64               `json:"p95_scan_duration_seconds"`
	Totals                 dashboardTotals       `json:"totals"`
	Config                 dashboardConfigPublic `json:"config"`
}

type dashboardRulesResponse struct {
	RuleSets      []RuleSetInfo `json:"rule_sets"`
	TotalRuleSets int           `json:"total_rule_sets"`
	TotalRules    int           `json:"total_rules"`
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
		rulesTotal := 0
		for _, rs := range opts.RuleInventory {
			rulesTotal += rs.RuleCount
		}

		response := dashboardSummaryResponse{
			UptimeSeconds:          snapshot.UptimeSeconds,
			LastUpdated:            snapshot.LastUpdate,
			P95ScanDurationSeconds: snapshot.ScanDurationSeconds.P95,
			Totals: dashboardTotals{
				Requests:      snapshot.TotalRequests,
				Injections:    snapshot.TotalInjectionDetections,
				RateLimit:     snapshot.TotalRateLimitEvents,
				RuleSetCount:  len(opts.RuleInventory),
				LoadedRuleCnt: rulesTotal,
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
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		totalRules := 0
		for _, rs := range opts.RuleInventory {
			totalRules += rs.RuleCount
		}
		rules := opts.RuleInventory
		if rules == nil {
			rules = make([]RuleSetInfo, 0)
		}
		writeDashboardJSON(w, dashboardRulesResponse{
			RuleSets:      rules,
			TotalRuleSets: len(rules),
			TotalRules:    totalRules,
		})
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
	mux.Handle(dashboardAPI+"/rules", authMiddleware(rulesHandler))
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
	w.Header().Set("Content-Type", "application/json")
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
