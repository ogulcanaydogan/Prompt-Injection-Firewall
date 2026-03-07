package benchmarks

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ogulcanaydogan/Prompt-Injection-Firewall/pkg/detector"
	"github.com/ogulcanaydogan/Prompt-Injection-Firewall/pkg/rules"
)

type sample struct {
	ID       string `json:"id"`
	Text     string `json:"text"`
	Label    string `json:"label"`
	Category string `json:"category"`
}

type dataset struct {
	Samples []sample `json:"samples"`
}

func loadDataset(t *testing.T, filename string) []sample {
	t.Helper()
	dir, err := os.Getwd()
	require.NoError(t, err)

	// Walk up to find benchmarks/dataset
	for {
		candidate := filepath.Join(dir, "benchmarks", "dataset", filename)
		if _, err := os.Stat(candidate); err == nil {
			data, err := os.ReadFile(candidate)
			require.NoError(t, err)
			var ds dataset
			require.NoError(t, json.Unmarshal(data, &ds))
			return ds.Samples
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			// Try current directory
			candidate = filepath.Join("dataset", filename)
			data, err := os.ReadFile(candidate)
			if err != nil {
				t.Skipf("dataset file %s not found", filename)
				return nil
			}
			var ds dataset
			require.NoError(t, json.Unmarshal(data, &ds))
			return ds.Samples
		}
		dir = parent
	}
}

func TestAccuracy_Injections(t *testing.T) {
	samples := loadDataset(t, "injections.json")
	if len(samples) == 0 {
		t.Skip("no injection samples found")
	}

	rulesDir := findRulesDir(t)
	sets, err := rules.LoadDir(rulesDir)
	require.NoError(t, err)
	d, err := detector.NewRegexDetector(sets...)
	require.NoError(t, err)

	ctx := context.Background()

	detected := 0
	missed := 0
	var missedSamples []string

	for _, s := range samples {
		result, err := d.Scan(ctx, detector.ScanInput{Text: s.Text})
		require.NoError(t, err)

		if !result.Clean {
			detected++
		} else {
			missed++
			missedSamples = append(missedSamples, s.ID+": "+s.Text[:min(80, len(s.Text))])
		}
	}

	rate := float64(detected) / float64(len(samples)) * 100
	t.Logf("Detection rate: %.1f%% (%d/%d)", rate, detected, len(samples))
	t.Logf("Missed: %d samples", missed)
	for _, m := range missedSamples {
		t.Logf("  MISSED: %s", m)
	}

	assert.GreaterOrEqual(t, rate, 80.0, "detection rate should be at least 80%%")
}

func TestAccuracy_Benign(t *testing.T) {
	samples := loadDataset(t, "benign.json")
	if len(samples) == 0 {
		t.Skip("no benign samples found")
	}

	rulesDir := findRulesDir(t)
	sets, err := rules.LoadDir(rulesDir)
	require.NoError(t, err)
	d, err := detector.NewRegexDetector(sets...)
	require.NoError(t, err)

	ctx := context.Background()

	clean := 0
	falsePositives := 0
	var fpSamples []string

	for _, s := range samples {
		result, err := d.Scan(ctx, detector.ScanInput{Text: s.Text})
		require.NoError(t, err)

		if result.Clean {
			clean++
		} else {
			falsePositives++
			rules := ""
			for _, f := range result.Findings {
				rules += f.RuleID + " "
			}
			fpSamples = append(fpSamples, s.ID+": ["+rules+"] "+s.Text[:min(80, len(s.Text))])
		}
	}

	fpRate := float64(falsePositives) / float64(len(samples)) * 100
	t.Logf("False positive rate: %.1f%% (%d/%d)", fpRate, falsePositives, len(samples))
	for _, fp := range fpSamples {
		t.Logf("  FALSE POSITIVE: %s", fp)
	}

	assert.LessOrEqual(t, fpRate, 10.0, "false positive rate should be at most 10%%")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
