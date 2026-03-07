package webhook

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"
)

// ServerOptions configures the admission webhook server.
type ServerOptions struct {
	Listen         string
	TLSCertFile    string
	TLSKeyFile     string
	PIFHostPattern string
}

// StartServer starts the validating admission webhook server.
func StartServer(opts ServerOptions) error {
	if strings.TrimSpace(opts.Listen) == "" {
		opts.Listen = ":8443"
	}
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	validator, err := newValidator(opts.PIFHostPattern)
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	mux.Handle("/validate", validateHandler(validator, logger))

	server := &http.Server{
		Addr:         opts.Listen,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	logger.Info("PIF admission webhook started",
		"listen", opts.Listen,
		"pif_host_pattern", validator.pifHostPattern,
	)

	if opts.TLSCertFile != "" && opts.TLSKeyFile != "" {
		return server.ListenAndServeTLS(opts.TLSCertFile, opts.TLSKeyFile)
	}
	return server.ListenAndServe()
}

func validateHandler(v *validator, logger *slog.Logger) http.Handler {
	logger = ensureWebhookLogger(logger)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, "reading request body", http.StatusBadRequest)
			return
		}

		var review AdmissionReview
		if err := json.Unmarshal(body, &review); err != nil {
			http.Error(w, "invalid AdmissionReview payload", http.StatusBadRequest)
			return
		}
		if review.Request == nil {
			http.Error(w, "missing admission request", http.StatusBadRequest)
			return
		}

		allowed, message, validationErr := evaluateAdmissionRequest(v, review.Request)
		if validationErr != nil {
			logger.Error("validation error", "error", validationErr)
			allowed = false
			message = fmt.Sprintf("validation error: %v", validationErr)
		}

		resp := AdmissionReview{
			APIVersion: "admission.k8s.io/v1",
			Kind:       "AdmissionReview",
			Response: &AdmissionResponse{
				UID:     review.Request.UID,
				Allowed: allowed,
			},
		}
		if !allowed {
			resp.Response.Result = &Status{
				Code:    http.StatusForbidden,
				Message: message,
			}
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			logger.Error("writing admission response", "error", err)
		}
	})
}

func evaluateAdmissionRequest(v *validator, req *AdmissionRequest) (bool, string, error) {
	operation := strings.ToUpper(strings.TrimSpace(req.Operation))
	if operation != "CREATE" && operation != "UPDATE" {
		return true, "", nil
	}

	kind := strings.TrimSpace(req.Kind.Kind)
	if _, ok := supportedKinds[kind]; !ok {
		return true, "", nil
	}

	return v.validate(kind, req.Object)
}

func ensureWebhookLogger(logger *slog.Logger) *slog.Logger {
	if logger != nil {
		return logger
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
