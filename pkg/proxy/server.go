package proxy

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"

	"github.com/yapay-ai/prompt-injection-firewall/pkg/detector"
)

// StartServer starts the PIF reverse proxy server.
func StartServer(targetURL, listen, actionStr string, d detector.Detector) error {
	target, err := url.Parse(targetURL)
	if err != nil {
		return fmt.Errorf("parsing target URL: %w", err)
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

	action := ParseAction(actionStr)
	middleware := ScanMiddleware(d, action, 0.5, logger)
	handler := middleware(proxy)

	// Health check endpoint
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})
	mux.Handle("/", handler)

	server := &http.Server{
		Addr:         listen,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	logger.Info("PIF proxy started",
		"listen", listen,
		"target", targetURL,
		"action", actionStr,
	)

	return server.ListenAndServe()
}
