//go:build !ml

package detector

import (
	"context"
	"errors"
)

// ErrMLNotAvailable is returned when the ML detector is not compiled into the binary.
// Build with -tags ml to enable ML-based detection.
var ErrMLNotAvailable = errors.New("ML detector not available: build with -tags ml and CGO_ENABLED=1")

// MLDetector is a stub implementation used when the binary is built without
// the "ml" build tag. All methods return ErrMLNotAvailable.
type MLDetector struct{}

// MLConfig holds configuration for the ML detector.
type MLConfig struct {
	ModelPath string  // Path to ONNX model directory or HuggingFace model ID
	Threshold float64 // Minimum confidence to flag as injection (0.0-1.0)
}

// NewMLDetector returns ErrMLNotAvailable when built without the ml tag.
func NewMLDetector(cfg MLConfig) (*MLDetector, error) {
	return nil, ErrMLNotAvailable
}

// ID returns the detector identifier.
func (m *MLDetector) ID() string { return "ml" }

// Scan always returns ErrMLNotAvailable in the stub build.
func (m *MLDetector) Scan(_ context.Context, _ ScanInput) (*ScanResult, error) {
	return nil, ErrMLNotAvailable
}

// Ready always returns false in the stub build.
func (m *MLDetector) Ready() bool { return false }

// Close is a no-op in the stub build.
func (m *MLDetector) Close() error { return nil }
