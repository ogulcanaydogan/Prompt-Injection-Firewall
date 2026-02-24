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
	ActionFlag               // Add header X-PIF-Flagged: true, forward anyway
	ActionLog                // Log only, forward normally
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

const maxBodySize = 1 << 20 // 1MB

// ScanMiddleware intercepts requests, scans prompt content, and applies the configured action.
func ScanMiddleware(d detector.Detector, action Action, threshold float64, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Only scan POST requests (chat completions, messages)
			if r.Method != http.MethodPost {
				next.ServeHTTP(w, r)
				return
			}

			// Read body
			body, err := io.ReadAll(io.LimitReader(r.Body, maxBodySize))
			r.Body.Close()
			if err != nil {
				logger.Error("reading request body", "error", err)
				next.ServeHTTP(w, r)
				return
			}

			// Restore body for forwarding
			r.Body = io.NopCloser(bytes.NewReader(body))

			// Extract prompts based on the API format
			inputs := extractPrompts(body, r.URL.Path)
			if len(inputs) == 0 {
				next.ServeHTTP(w, r)
				return
			}

			// Scan all messages
			ctx, cancel := context.WithTimeout(r.Context(), 50*time.Millisecond)
			defer cancel()

			var allFindings []detector.Finding
			var maxScore float64

			for _, input := range inputs {
				result, err := d.Scan(ctx, input)
				if err != nil {
					logger.Warn("scan error", "error", err)
					continue
				}

				allFindings = append(allFindings, result.Findings...)
				if result.Score > maxScore {
					maxScore = result.Score
				}
			}

			isInjection := len(allFindings) > 0 && maxScore >= threshold

			if isInjection {
				logger.Warn("injection detected",
					"score", maxScore,
					"findings", len(allFindings),
					"action", actionString(action),
				)

				switch action {
				case ActionBlock:
					writeBlockResponse(w, maxScore, allFindings)
					return
				case ActionFlag:
					w.Header().Set("X-PIF-Flagged", "true")
					w.Header().Set("X-PIF-Score", formatScore(maxScore))
				case ActionLog:
					// just log, already done above
				}
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

func writeBlockResponse(w http.ResponseWriter, score float64, findings []detector.Finding) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)

	resp := map[string]interface{}{
		"error": map[string]interface{}{
			"message": "Request blocked by Prompt Injection Firewall",
			"type":    "prompt_injection_detected",
			"score":   score,
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
