package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// findRulesDir walks up directories to find the project's rules/ directory.
func findRulesDir(t *testing.T) string {
	t.Helper()

	// Walk up from test file location to find project root
	candidates := []string{
		"../../rules",    // internal/cli -> project root
		"../../../rules", // fallback
		"rules",          // already at root
	}

	for _, c := range candidates {
		abs, err := filepath.Abs(c)
		if err != nil {
			continue
		}
		if info, err := os.Stat(abs); err == nil && info.IsDir() {
			return abs
		}
	}

	t.Fatal("could not find rules directory")
	return ""
}

func TestNewRulesCmd_Structure(t *testing.T) {
	cmd := newRulesCmd()

	assert.Equal(t, "rules", cmd.Use)
	assert.Contains(t, cmd.Short, "Manage detection rules")

	subcommands := make(map[string]bool)
	for _, sub := range cmd.Commands() {
		subcommands[sub.Name()] = true
	}

	assert.True(t, subcommands["list"], "should have list subcommand")
	assert.True(t, subcommands["validate"], "should have validate subcommand")
}

func TestRulesListCmd_ValidDir(t *testing.T) {
	rulesDir := findRulesDir(t)

	cmd := newRulesCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"list", rulesDir})

	err := cmd.Execute()
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "Total:")
	assert.Contains(t, output, "rules")
	// Should contain rule IDs from our YAML files
	assert.Contains(t, output, "ID")
	assert.Contains(t, output, "CATEGORY")
	assert.Contains(t, output, "SEVERITY")
}

func TestRulesListCmd_InvalidDir(t *testing.T) {
	cmd := newRulesCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"list", "/nonexistent/path"})

	err := cmd.Execute()
	assert.Error(t, err)
}

func TestRulesValidateCmd_ValidRules(t *testing.T) {
	rulesDir := findRulesDir(t)

	cmd := newRulesCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"validate", rulesDir})

	err := cmd.Execute()
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "OK")
	assert.Contains(t, output, "validated successfully")
}

func TestRulesValidateCmd_InvalidDir(t *testing.T) {
	cmd := newRulesCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"validate", "/nonexistent/path"})

	err := cmd.Execute()
	assert.Error(t, err)
}
