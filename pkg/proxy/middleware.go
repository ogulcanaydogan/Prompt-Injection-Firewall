package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/ogulcanaydogan/Prompt-Injection-Firewall/pkg/detector"
)

// Action defines what happens when an injection is detected.
type Action int

const (
	ActionBlock Action = iota // Return 403 Forbidden
	ActionFlag                // Add header X-PIF-Flagged: true, forward anyway
	ActionLog                 // Log only, forward normally
)

// ParseAction converts a string to an Action.
func ParseAction(s string) Action {
	switch strings.ToLower(s) {
	case "block":
		return ActionBlock
	case "flag":
		return ActionFlag
	case "log":
		return ActionLog
	default:
		return ActionBlock
	}
}

// ScanMiddleware intercepts requests, scans prompt content, and applies the configured action.
func ScanMiddleware(d detector.Detector, action Action, threshold float64, logger *slog.Logger) func(http.Handler) http.Handler {
	opts := MiddlewareOptions{
		Threshold:   threshold,
		MaxBodySize: defaultMaxBodySize,
		ScanTimeout: defaultScanTimeout,
		Logger:      logger,
	}
	return ScanMiddlewareWithOptions(d, action, opts)
}

// ScanMiddlewareWithOptions intercepts requests, scans prompt content, and applies
// the configured action with rate-limiting, adaptive thresholds, and metrics.
func ScanMiddlewareWithOptions(d detector.Detector, action Action, opts MiddlewareOptions) func(http.Handler) http.Handler {
	logger := ensureLogger(opts.Logger)
	if opts.MaxBodySize <= 0 {
		opts.MaxBodySize = defaultMaxBodySize
	}
	if opts.ScanTimeout <= 0 {
		opts.ScanTimeout = defaultScanTimeout
	}
	if opts.Threshold <= 0 {
		opts.Threshold = 0.5
	}

	var limiter *perClientRateLimiter
	if opts.RateLimit.Enabled {
		limiter = newPerClientRateLimiter(opts.RateLimit)
	}
	adaptive := newAdaptiveThresholdState(opts.AdaptiveThreshold)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			actionLabel := actionString(action)
			outcome := "forwarded"
			defer func() {
				opts.Metrics.ObserveHTTPRequest(r.Method, actionLabel, outcome)
			}()

			clientKey := requestKeyFromRequest(r, opts.RateLimit.KeyHeader)
			if limiter != nil {
				if !limiter.allow(clientKey) {
					outcome = "rate_limited"
					opts.Metrics.IncRateLimitEvent("exceeded")
					writeRateLimitResponse(w)
					return
				}
			}

			// Only scan POST requests (chat completions, messages)
			if r.Method != http.MethodPost {
				outcome = "skipped_method"
				next.ServeHTTP(w, r)
				return
			}

			// Read body
			body, err := io.ReadAll(io.LimitReader(r.Body, opts.MaxBodySize))
			r.Body.Close()
			if err != nil {
				logger.Error("reading request body", "error", err)
				outcome = "body_read_error"
				next.ServeHTTP(w, r)
				return
			}

			// Restore body for forwarding
			r.Body = io.NopCloser(bytes.NewReader(body))

			// Extract prompts based on the API format
			inputs := extractPrompts(body, r.URL.Path)
			if len(inputs) == 0 {
				outcome = "skipped_no_inputs"
				next.ServeHTTP(w, r)
				return
			}

			// Scan all messages
			scanStart := time.Now()
			ctx, cancel := context.WithTimeout(r.Context(), opts.ScanTimeout)
			defer cancel()

			var allFindings []detector.Finding
			var maxScore float64
			scanErrors := 0

			for _, input := range inputs {
				result, err := d.Scan(ctx, input)
				if err != nil {
					logger.Warn("scan error", "error", err)
					scanErrors++
					continue
				}

				allFindings = append(allFindings, result.Findings...)
				if result.Score > maxScore {
					maxScore = result.Score
				}
			}

			effectiveThreshold := opts.Threshold
			if adaptive != nil {
				effectiveThreshold = adaptive.effectiveThreshold(clientKey, opts.Threshold)
			}
			isInjection := len(allFindings) > 0 && maxScore >= effectiveThreshold
			if adaptive != nil {
				adaptive.update(clientKey, isInjection)
			}

			scanOutcome := "clean"
			if isInjection {
				scanOutcome = "injection"
			} else if len(allFindings) > 0 {
				scanOutcome = "below_threshold"
			} else if scanErrors > 0 {
				scanOutcome = "scan_error"
			}
			opts.Metrics.ObserveScanDuration(time.Since(scanStart).Seconds(), scanOutcome)
			opts.Metrics.ObserveDetectionScore(maxScore, scanOutcome)

			if isInjection {
				opts.Metrics.IncInjectionDetection(actionLabel)
				logger.Warn("injection detected",
					"score", maxScore,
					"threshold", effectiveThreshold,
					"findings", len(allFindings),
					"action", actionLabel,
				)

				switch action {
				case ActionBlock:
					outcome = "blocked"
					writeBlockResponse(w, maxScore, allFindings)
					return
				case ActionFlag:
					outcome = "flagged"
					w.Header().Set("X-PIF-Flagged", "true")
					w.Header().Set("X-PIF-Score", formatScore(maxScore))
				case ActionLog:
					outcome = "logged"
					// just log, already done above
				}
			} else if len(allFindings) > 0 {
				outcome = "forwarded_below_threshold"
			}

			next.ServeHTTP(w, r)
		})
	}
}

func extractPrompts(body []byte, path string) []detector.ScanInput {
	// Try Anthropic format first (check for system field)
	if inputs, err := ExtractPromptsFromAnthropic(body); err == nil && len(inputs) > 0 {
		// Check if it looks like an Anthropic request (has system field or anthropic path)
		if strings.Contains(path, "anthropic") || strings.Contains(path, "messages") {
			return inputs
		}
	}

	// Default to OpenAI format
	if inputs, err := ExtractPromptsFromOpenAI(body); err == nil && len(inputs) > 0 {
		return inputs
	}

	return nil
}

func writeRateLimitResponse(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusTooManyRequests)

	resp := map[string]interface{}{
		"error": map[string]interface{}{
			"message": "Request rate-limited by Prompt Injection Firewall",
			"type":    "rate_limit_exceeded",
		},
	}

	_ = json.NewEncoder(w).Encode(resp)
}

func writeBlockResponse(w http.ResponseWriter, score float64, findings []detector.Finding) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)

	resp := map[string]interface{}{
		"error": map[string]interface{}{
			"message":  "Request blocked by Prompt Injection Firewall",
			"type":     "prompt_injection_detected",
			"score":    score,
			"findings": len(findings),
		},
	}

	json.NewEncoder(w).Encode(resp)
}

func actionString(a Action) string {
	switch a {
	case ActionBlock:
		return "block"
	case ActionFlag:
		return "flag"
	case ActionLog:
		return "log"
	default:
		return "unknown"
	}
}

func formatScore(score float64) string {
	return fmt.Sprintf("%.2f", score)
}

func ensureLogger(logger *slog.Logger) *slog.Logger {
	if logger != nil {
		return logger
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
