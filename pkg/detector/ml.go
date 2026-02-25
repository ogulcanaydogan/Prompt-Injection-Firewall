//go:build ml

package detector

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/knights-analytics/hugot"
	"github.com/knights-analytics/hugot/pipelines"
)

// MLDetector uses a fine-tuned DistilBERT ONNX model to detect prompt injection
// via semantic analysis. It implements the Detector interface and is only available
// when built with the "ml" build tag (requires CGO_ENABLED=1).
type MLDetector struct {
	session  *hugot.Session
	pipeline *pipelines.TextClassificationPipeline
	config   MLConfig
	mu       sync.RWMutex
	ready    bool
}

// MLConfig holds configuration for the ML detector.
type MLConfig struct {
	ModelPath string  // Path to ONNX model directory or HuggingFace model ID
	Threshold float64 // Minimum confidence to flag as injection (0.0-1.0)
}

// NewMLDetector loads an ONNX model and creates a text classification pipeline.
func NewMLDetector(cfg MLConfig) (*MLDetector, error) {
	if cfg.ModelPath == "" {
		return nil, fmt.Errorf("ML model path is required")
	}

	if cfg.Threshold <= 0 {
		cfg.Threshold = 0.85
	}

	// Check if model path exists on disk
	if _, err := os.Stat(cfg.ModelPath); err != nil {
		return nil, fmt.Errorf("model path not found: %s: %w", cfg.ModelPath, err)
	}

	// Create ONNX Runtime session
	session, err := hugot.NewSession(
		hugot.WithOnnxLibraryPath(""), // use default ONNX Runtime location
	)
	if err != nil {
		return nil, fmt.Errorf("creating ONNX session: %w", err)
	}

	// Create text classification pipeline
	pipeline, err := session.NewTextClassificationPipeline(
		cfg.ModelPath,
		"pif-injection-classifier",
		pipelines.WithSingleLabel(),
	)
	if err != nil {
		session.Destroy()
		return nil, fmt.Errorf("creating classification pipeline: %w", err)
	}

	return &MLDetector{
		session:  session,
		pipeline: pipeline,
		config:   cfg,
		ready:    true,
	}, nil
}

// ID returns the detector identifier.
func (m *MLDetector) ID() string { return "ml" }

// Ready reports whether the ML detector is initialized and operational.
func (m *MLDetector) Ready() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.ready
}

// Scan analyzes input text using the DistilBERT model and returns detection results.
func (m *MLDetector) Scan(ctx context.Context, input ScanInput) (*ScanResult, error) {
	m.mu.RLock()
	if !m.ready {
		m.mu.RUnlock()
		return nil, fmt.Errorf("ML detector not ready")
	}
	m.mu.RUnlock()

	// Check context cancellation
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	start := time.Now()

	// Run inference
	result, err := m.pipeline.RunPipeline([]string{input.Text})
	if err != nil {
		return nil, fmt.Errorf("ML inference failed: %w", err)
	}

	// Check context again after inference
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// Compute input hash
	h := sha256.Sum256([]byte(input.Text))
	hash := fmt.Sprintf("%x", h)

	// Parse classification results
	scanResult := &ScanResult{
		Clean:      true,
		Score:      0,
		DetectorID: "ml",
		Duration:   time.Since(start),
		InputHash:  hash,
	}

	// Process model output
	if len(result.ClassificationOutputs) > 0 && len(result.ClassificationOutputs[0]) > 0 {
		output := result.ClassificationOutputs[0]

		// Find the injection class score
		for _, cls := range output {
			if cls.Label == "INJECTION" || cls.Label == "LABEL_1" {
				if cls.Score >= float32(m.config.Threshold) {
					scanResult.Clean = false
					scanResult.Score = float64(cls.Score)
					scanResult.Findings = []Finding{
						{
							RuleID:      "PIF-ML-001",
							Category:    CategoryPromptInjection,
							Severity:    mapConfidenceToSeverity(float64(cls.Score)),
							Description: "ML model detected potential prompt injection",
							MatchedText: truncateText(input.Text, 80),
							Offset:      0,
							Length:       len(input.Text),
							Metadata: map[string]string{
								"detector":   "distilbert-onnx",
								"confidence": fmt.Sprintf("%.4f", cls.Score),
							},
						},
					}
				}
				break
			}
		}
	}

	return scanResult, nil
}

// Close releases ONNX Runtime resources.
func (m *MLDetector) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.ready = false
	if m.session != nil {
		m.session.Destroy()
		m.session = nil
	}
	return nil
}

// mapConfidenceToSeverity maps ML confidence score to PIF severity levels.
func mapConfidenceToSeverity(confidence float64) Severity {
	switch {
	case confidence >= 0.95:
		return SeverityCritical
	case confidence >= 0.90:
		return SeverityHigh
	case confidence >= 0.85:
		return SeverityMedium
	case confidence >= 0.75:
		return SeverityLow
	default:
		return SeverityInfo
	}
}

// truncateText truncates text to maxLen characters with ellipsis.
func truncateText(text string, maxLen int) string {
	if len(text) <= maxLen {
		return text
	}
	return text[:maxLen-3] + "..."
}
