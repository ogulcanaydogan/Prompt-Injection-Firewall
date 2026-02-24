package detector

import "context"

// Detector is the core interface that all detection engines implement.
type Detector interface {
	// ID returns a unique identifier for this detector.
	ID() string

	// Scan analyzes input text and returns detection results.
	Scan(ctx context.Context, input ScanInput) (*ScanResult, error)

	// Ready reports whether the detector is initialized and operational.
	Ready() bool
}
