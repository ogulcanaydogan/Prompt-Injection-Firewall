package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ogulcanaydogan/Prompt-Injection-Firewall/pkg/detector"
)

func cleanResult() *detector.ScanResult {
	return &detector.ScanResult{
		Clean:      true,
		Score:      0.0,
		Findings:   nil,
		DetectorID: "test-detector",
		Duration:   5 * time.Millisecond,
		InputHash:  "abc123",
	}
}

func maliciousResult() *detector.ScanResult {
	return &detector.ScanResult{
		Clean: false,
		Score: 0.85,
		Findings: []detector.Finding{
			{
				RuleID:      "PIF-INJ-001",
				Category:    detector.CategoryPromptInjection,
				Severity:    detector.SeverityCritical,
				Description: "Detects attempts to override system instructions",
				MatchedText: "ignore all previous instructions",
				Offset:      0,
				Length:      31,
			},
			{
				RuleID:      "PIF-LLM07-001",
				Category:    detector.CategorySystemPromptLeak,
				Severity:    detector.SeverityHigh,
				Description: "Detects system prompt extraction attempts",
				MatchedText: "reveal your system prompt",
				Offset:      36,
				Length:      25,
			},
		},
		DetectorID: "test-detector",
		Duration:   12 * time.Millisecond,
		InputHash:  "def456",
	}
}

func TestPrintJSON_CleanResult(t *testing.T) {
	var buf bytes.Buffer
	err := printJSON(&buf, cleanResult())
	require.NoError(t, err)

	var output map[string]interface{}
	err = json.Unmarshal(buf.Bytes(), &output)
	require.NoError(t, err)

	assert.Equal(t, true, output["clean"])
	assert.Equal(t, float64(0), output["score"])
	assert.Equal(t, "test-detector", output["detector_id"])
	assert.Equal(t, "abc123", output["input_hash"])
}

func TestPrintJSON_MaliciousResult(t *testing.T) {
	var buf bytes.Buffer
	err := printJSON(&buf, maliciousResult())
	require.NoError(t, err)

	var output map[string]interface{}
	err = json.Unmarshal(buf.Bytes(), &output)
	require.NoError(t, err)

	assert.Equal(t, false, output["clean"])
	assert.Equal(t, 0.85, output["score"])
	assert.Equal(t, "def456", output["input_hash"])

	findings, ok := output["findings"].([]interface{})
	require.True(t, ok)
	assert.Len(t, findings, 2)

	first := findings[0].(map[string]interface{})
	assert.Equal(t, "PIF-INJ-001", first["rule_id"])
	assert.Equal(t, "prompt_injection", first["category"])
}

func TestPrintJSON_DurationField(t *testing.T) {
	var buf bytes.Buffer
	result := cleanResult()
	result.Duration = 10 * time.Millisecond

	err := printJSON(&buf, result)
	require.NoError(t, err)

	var output map[string]interface{}
	err = json.Unmarshal(buf.Bytes(), &output)
	require.NoError(t, err)

	durationMs, ok := output["duration_ms"].(float64)
	require.True(t, ok)
	assert.Greater(t, durationMs, 0.0)
}

func TestPrintTable_CleanResult(t *testing.T) {
	var buf bytes.Buffer
	err := printTable(&buf, cleanResult(), 0.5, false)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "CLEAN")
	assert.Contains(t, output, "score: 0.00")
}

func TestPrintTable_InjectionDetected(t *testing.T) {
	var buf bytes.Buffer
	err := printTable(&buf, maliciousResult(), 0.5, false)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "INJECTION DETECTED")
	assert.Contains(t, output, "score: 0.85")
	assert.Contains(t, output, "PIF-INJ-001")
	assert.Contains(t, output, "prompt_injection")
	assert.Contains(t, output, "critical")
	assert.Contains(t, output, "2 finding(s)")
}

func TestPrintTable_BelowThreshold(t *testing.T) {
	result := maliciousResult()
	result.Score = 0.3 // below default threshold

	var buf bytes.Buffer
	err := printTable(&buf, result, 0.5, false)
	require.NoError(t, err)

	assert.Contains(t, buf.String(), "CLEAN")
}

func TestPrintTable_TruncatesLongText(t *testing.T) {
	result := &detector.ScanResult{
		Clean: false,
		Score: 0.9,
		Findings: []detector.Finding{
			{
				RuleID:      "PIF-TEST-001",
				Category:    detector.CategoryPromptInjection,
				Severity:    detector.SeverityHigh,
				MatchedText: strings.Repeat("a", 80), // longer than 50 chars
				Offset:      0,
				Length:      80,
			},
		},
		DetectorID: "test",
		Duration:   1 * time.Millisecond,
	}

	var buf bytes.Buffer
	err := printTable(&buf, result, 0.5, false)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "...")
}

func TestPrintTable_VerboseMode(t *testing.T) {
	var buf bytes.Buffer
	err := printTable(&buf, maliciousResult(), 0.5, true)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "Description:")
	assert.Contains(t, output, "Offset:")
	assert.Contains(t, output, "Length:")
}
