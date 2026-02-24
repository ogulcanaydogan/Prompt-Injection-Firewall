package detector

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sync"
	"time"
)

// EnsembleStrategy defines how multiple detector results are combined.
type EnsembleStrategy int

const (
	StrategyAnyMatch EnsembleStrategy = iota // flag if ANY detector fires
	StrategyMajority                         // flag if majority of detectors agree
	StrategyWeighted                         // weighted score aggregation
)

// EnsembleDetector runs multiple detectors concurrently and merges results.
type EnsembleDetector struct {
	detectors []weightedDetector
	strategy  EnsembleStrategy
	timeout   time.Duration
}

type weightedDetector struct {
	detector Detector
	weight   float64
}

type detectorResult struct {
	result *ScanResult
	weight float64
	err    error
}

// NewEnsemble creates a new ensemble with the given strategy.
func NewEnsemble(strategy EnsembleStrategy, timeout time.Duration) *EnsembleDetector {
	return &EnsembleDetector{
		strategy: strategy,
		timeout:  timeout,
	}
}

// Register adds a detector with a weight to the ensemble.
func (e *EnsembleDetector) Register(d Detector, weight float64) {
	e.detectors = append(e.detectors, weightedDetector{detector: d, weight: weight})
}

func (e *EnsembleDetector) ID() string  { return "ensemble" }
func (e *EnsembleDetector) Ready() bool { return len(e.detectors) > 0 }

// RuleCount returns the total number of rules across all regex detectors.
func (e *EnsembleDetector) RuleCount() int {
	total := 0
	for _, wd := range e.detectors {
		if rd, ok := wd.detector.(*RegexDetector); ok {
			total += rd.RuleCount()
		}
	}
	return total
}

// Scan runs all registered detectors concurrently and merges results.
func (e *EnsembleDetector) Scan(ctx context.Context, input ScanInput) (*ScanResult, error) {
	start := time.Now()

	if len(e.detectors) == 0 {
		return &ScanResult{Clean: true, DetectorID: e.ID()}, nil
	}

	ctx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	results := make(chan detectorResult, len(e.detectors))

	var wg sync.WaitGroup
	for _, wd := range e.detectors {
		wg.Add(1)
		go func(wd weightedDetector) {
			defer wg.Done()
			r, err := wd.detector.Scan(ctx, input)
			results <- detectorResult{result: r, weight: wd.weight, err: err}
		}(wd)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var collected []detectorResult
	for dr := range results {
		if dr.err != nil {
			continue // skip failed detectors
		}
		collected = append(collected, dr)
	}

	if len(collected) == 0 {
		return nil, fmt.Errorf("all detectors failed")
	}

	merged := e.merge(collected, input)
	merged.Duration = time.Since(start)

	return merged, nil
}

func (e *EnsembleDetector) merge(results []detectorResult, input ScanInput) *ScanResult {
	h := sha256.Sum256([]byte(input.Text))
	hash := fmt.Sprintf("%x", h)

	switch e.strategy {
	case StrategyAnyMatch:
		return e.mergeAny(results, hash)
	case StrategyMajority:
		return e.mergeMajority(results, hash)
	case StrategyWeighted:
		return e.mergeWeighted(results, hash)
	default:
		return e.mergeAny(results, hash)
	}
}

func (e *EnsembleDetector) mergeAny(results []detectorResult, hash string) *ScanResult {
	var allFindings []Finding
	var maxScore float64

	for _, dr := range results {
		allFindings = append(allFindings, dr.result.Findings...)
		if dr.result.Score > maxScore {
			maxScore = dr.result.Score
		}
	}

	return &ScanResult{
		Clean:      len(allFindings) == 0,
		Score:      maxScore,
		Findings:   deduplicateFindings(allFindings),
		DetectorID: "ensemble",
		InputHash:  hash,
	}
}

func (e *EnsembleDetector) mergeMajority(results []detectorResult, hash string) *ScanResult {
	dirty := 0
	for _, dr := range results {
		if !dr.result.Clean {
			dirty++
		}
	}

	isMajority := dirty > len(results)/2

	var allFindings []Finding
	var maxScore float64
	for _, dr := range results {
		allFindings = append(allFindings, dr.result.Findings...)
		if dr.result.Score > maxScore {
			maxScore = dr.result.Score
		}
	}

	if !isMajority {
		return &ScanResult{
			Clean:      true,
			Score:      0,
			DetectorID: "ensemble",
			InputHash:  hash,
		}
	}

	return &ScanResult{
		Clean:      false,
		Score:      maxScore,
		Findings:   deduplicateFindings(allFindings),
		DetectorID: "ensemble",
		InputHash:  hash,
	}
}

func (e *EnsembleDetector) mergeWeighted(results []detectorResult, hash string) *ScanResult {
	var totalWeight float64
	var weightedScore float64
	var allFindings []Finding

	for _, dr := range results {
		weightedScore += dr.result.Score * dr.weight
		totalWeight += dr.weight
		allFindings = append(allFindings, dr.result.Findings...)
	}

	score := 0.0
	if totalWeight > 0 {
		score = weightedScore / totalWeight
	}

	return &ScanResult{
		Clean:      len(allFindings) == 0,
		Score:      score,
		Findings:   deduplicateFindings(allFindings),
		DetectorID: "ensemble",
		InputHash:  hash,
	}
}

// deduplicateFindings removes duplicate findings by rule ID + offset.
func deduplicateFindings(findings []Finding) []Finding {
	seen := make(map[string]bool)
	var result []Finding

	for _, f := range findings {
		key := fmt.Sprintf("%s:%d", f.RuleID, f.Offset)
		if !seen[key] {
			seen[key] = true
			result = append(result, f)
		}
	}

	return result
}
