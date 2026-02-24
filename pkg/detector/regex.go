package detector

import (
	"context"
	"crypto/sha256"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/ogulcanaydogan/Prompt-Injection-Firewall/pkg/rules"
)

type compiledRule struct {
	rule    rules.Rule
	pattern *regexp.Regexp
}

// RegexDetector scans text using pre-compiled regex patterns.
type RegexDetector struct {
	id       string
	compiled []compiledRule
	mu       sync.RWMutex
}

// NewRegexDetector creates a detector from one or more rule sets.
// All patterns are compiled once at construction time.
func NewRegexDetector(ruleSets ...rules.RuleSet) (*RegexDetector, error) {
	merged := rules.MergeRuleSets(ruleSets)

	compiled := make([]compiledRule, 0, len(merged))
	for _, r := range merged {
		p := r.Pattern
		if !r.CaseSensitive && !strings.HasPrefix(p, "(?i)") {
			p = "(?i)" + p
		}

		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("compiling pattern for rule %s: %w", r.ID, err)
		}

		compiled = append(compiled, compiledRule{
			rule:    r,
			pattern: re,
		})
	}

	return &RegexDetector{
		id:       "regex",
		compiled: compiled,
	}, nil
}

func (d *RegexDetector) ID() string { return d.id }
func (d *RegexDetector) Ready() bool { return len(d.compiled) > 0 }

// Scan checks the input text against all compiled patterns.
func (d *RegexDetector) Scan(ctx context.Context, input ScanInput) (*ScanResult, error) {
	start := time.Now()

	d.mu.RLock()
	compiled := d.compiled
	d.mu.RUnlock()

	h := sha256.Sum256([]byte(input.Text))
	hash := fmt.Sprintf("%x", h)

	var findings []Finding

	for _, cr := range compiled {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		matches := cr.pattern.FindAllStringIndex(input.Text, -1)
		for _, loc := range matches {
			matched := input.Text[loc[0]:loc[1]]

			// Truncate matched text for output
			if len(matched) > 200 {
				matched = matched[:200] + "..."
			}

			findings = append(findings, Finding{
				RuleID:      cr.rule.ID,
				Category:    Category(cr.rule.Category),
				Severity:    Severity(cr.rule.Severity),
				Description: cr.rule.Description,
				MatchedText: matched,
				Offset:      loc[0],
				Length:       loc[1] - loc[0],
			})
		}
	}

	score := calculateScore(findings)

	return &ScanResult{
		Clean:      len(findings) == 0,
		Score:      score,
		Findings:   findings,
		DetectorID: d.id,
		Duration:   time.Since(start),
		InputHash:  hash,
	}, nil
}

// RuleCount returns the number of loaded rules.
func (d *RegexDetector) RuleCount() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.compiled)
}

// calculateScore computes a threat score from 0.0 to 1.0 based on findings.
func calculateScore(findings []Finding) float64 {
	if len(findings) == 0 {
		return 0.0
	}

	var maxSeverity Severity
	for _, f := range findings {
		if f.Severity > maxSeverity {
			maxSeverity = f.Severity
		}
	}

	// Base score from max severity
	base := float64(maxSeverity) / float64(SeverityCritical)

	// Boost for multiple findings (capped at 0.2 additional)
	boost := float64(len(findings)-1) * 0.05
	if boost > 0.2 {
		boost = 0.2
	}

	score := base + boost
	if score > 1.0 {
		score = 1.0
	}

	return score
}
