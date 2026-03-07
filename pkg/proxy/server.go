package proxy

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"

	"github.com/ogulcanaydogan/Prompt-Injection-Firewall/pkg/detector"
)

// StartServer starts the PIF reverse proxy server.
func StartServer(opts ServerOptions, d detector.Detector) error {
	target, err := url.Parse(opts.TargetURL)
	if err != nil {
		return fmt.Errorf("parsing target URL: %w", err)
	}
	if opts.Metrics == nil {
		opts.Metrics = NewMetrics()
	}
	if opts.ReadTimeout <= 0 {
		opts.ReadTimeout = 10 * time.Second
	}
	if opts.WriteTimeout <= 0 {
		opts.WriteTimeout = 30 * time.Second
	}
	if opts.IdleTimeout <= 0 {
		opts.IdleTimeout = 60 * time.Second
	}

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	proxy := httputil.NewSingleHostReverseProxy(target)

	// Preserve the original Host header
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.Host = target.Host
	}

	action := ParseAction(opts.Action)
	middleware := ScanMiddlewareWithOptions(d, action, MiddlewareOptions{
		Threshold:         opts.Threshold,
		MaxBodySize:       opts.MaxBodySize,
		ScanTimeout:       opts.ScanTimeout,
		Logger:            logger,
		Metrics:           opts.Metrics,
		RateLimit:         opts.RateLimit,
		AdaptiveThreshold: opts.AdaptiveThreshold,
	})
	handler := middleware(proxy)

	// Health check endpoint
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	mux.Handle("GET /metrics", opts.Metrics.Handler())

	if opts.Dashboard.Enabled {
		registerDashboardRoutes(mux, opts)
	} else {
		registerDashboardNotFoundRoutes(mux, opts.Dashboard.Path, opts.Dashboard.APIPrefix)
	}

	mux.Handle("/", handler)

	server := &http.Server{
		Addr:         opts.Listen,
		Handler:      mux,
		ReadTimeout:  opts.ReadTimeout,
		WriteTimeout: opts.WriteTimeout,
		IdleTimeout:  opts.IdleTimeout,
	}

	logger.Info("PIF proxy started",
		"listen", opts.Listen,
		"target", opts.TargetURL,
		"action", opts.Action,
	)

	return server.ListenAndServe()
}
