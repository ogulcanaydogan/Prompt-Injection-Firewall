package rules

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadFile(t *testing.T) {
	// Find the rules directory relative to the project root
	rulesDir := findRulesDir(t)

	t.Run("loads jailbreak patterns", func(t *testing.T) {
		rs, err := LoadFile(filepath.Join(rulesDir, "jailbreak-patterns.yaml"))
		require.NoError(t, err)
		assert.Equal(t, "Jailbreak & Injection Patterns", rs.Name)
		assert.NotEmpty(t, rs.Rules)
		assert.Equal(t, "1.0.0", rs.Version)
	})

	t.Run("loads data exfil patterns", func(t *testing.T) {
		rs, err := LoadFile(filepath.Join(rulesDir, "data-exfil.yaml"))
		require.NoError(t, err)
		assert.Equal(t, "Data Exfiltration & Encoding Attacks", rs.Name)
		assert.NotEmpty(t, rs.Rules)
	})

	t.Run("loads owasp patterns", func(t *testing.T) {
		rs, err := LoadFile(filepath.Join(rulesDir, "owasp-llm-top10.yaml"))
		require.NoError(t, err)
		assert.Equal(t, "OWASP LLM Top 10 - 2025", rs.Name)
		assert.NotEmpty(t, rs.Rules)
	})

	t.Run("returns error for nonexistent file", func(t *testing.T) {
		_, err := LoadFile("/nonexistent/file.yaml")
		assert.Error(t, err)
	})
}

func TestLoadFile_Validation(t *testing.T) {
	t.Run("rejects empty name", func(t *testing.T) {
		content := `name: ""
version: "1.0"
rules:
  - id: "test-001"
    pattern: "test"
    enabled: true`

		path := writeTempYAML(t, content)
		_, err := LoadFile(path)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "name is required")
	})

	t.Run("rejects duplicate rule IDs", func(t *testing.T) {
		content := `name: "Test"
version: "1.0"
rules:
  - id: "dupe-001"
    pattern: "test1"
    enabled: true
  - id: "dupe-001"
    pattern: "test2"
    enabled: true`

		path := writeTempYAML(t, content)
		_, err := LoadFile(path)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "duplicate rule id")
	})

	t.Run("rejects invalid regex", func(t *testing.T) {
		content := `name: "Test"
version: "1.0"
rules:
  - id: "bad-001"
    pattern: "[invalid"
    enabled: true`

		path := writeTempYAML(t, content)
		_, err := LoadFile(path)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid pattern")
	})

	t.Run("rejects missing pattern", func(t *testing.T) {
		content := `name: "Test"
version: "1.0"
rules:
  - id: "nopat-001"
    enabled: true`

		path := writeTempYAML(t, content)
		_, err := LoadFile(path)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "pattern is required")
	})
}

func TestLoadDir(t *testing.T) {
	rulesDir := findRulesDir(t)

	sets, err := LoadDir(rulesDir)
	require.NoError(t, err)
	assert.Len(t, sets, 3, "should load all 3 rule files")

	totalRules := 0
	for _, rs := range sets {
		totalRules += len(rs.Rules)
	}
	assert.GreaterOrEqual(t, totalRules, 50, "should have at least 50 rules total")
}

func TestMergeRuleSets(t *testing.T) {
	sets := []RuleSet{
		{
			Name: "Set1",
			Rules: []Rule{
				{ID: "r1", Enabled: true, Pattern: "a"},
				{ID: "r2", Enabled: false, Pattern: "b"},
			},
		},
		{
			Name: "Set2",
			Rules: []Rule{
				{ID: "r3", Enabled: true, Pattern: "c"},
			},
		},
	}

	merged := MergeRuleSets(sets)
	assert.Len(t, merged, 2, "should only include enabled rules")
	assert.Equal(t, "r1", merged[0].ID)
	assert.Equal(t, "r3", merged[1].ID)
}

func findRulesDir(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	require.NoError(t, err)

	for {
		candidate := filepath.Join(dir, "rules")
		// Check that the directory exists AND contains YAML rule files
		if _, err := os.Stat(filepath.Join(candidate, "jailbreak-patterns.yaml")); err == nil {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find rules directory with YAML files")
		}
		dir = parent
	}
}

func writeTempYAML(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "*.yaml")
	require.NoError(t, err)
	_, err = f.WriteString(content)
	require.NoError(t, err)
	require.NoError(t, f.Close())
	return f.Name()
}
