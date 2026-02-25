package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefault(t *testing.T) {
	cfg := Default()
	assert.Equal(t, 0.5, cfg.Detector.Threshold)
	assert.Equal(t, "low", cfg.Detector.MinSeverity)
	assert.Equal(t, 100, cfg.Detector.TimeoutMs)
	assert.Equal(t, "weighted", cfg.Detector.Strategy)
	assert.Equal(t, "", cfg.Detector.MLModelPath)
	assert.Equal(t, 0.85, cfg.Detector.MLThreshold)
	assert.Equal(t, 0.6, cfg.Detector.Weights.Regex)
	assert.Equal(t, 0.4, cfg.Detector.Weights.ML)
	assert.Equal(t, ":8080", cfg.Proxy.Listen)
	assert.Equal(t, "block", cfg.Proxy.Action)
	assert.Equal(t, "info", cfg.Logging.Level)
	assert.False(t, cfg.Logging.LogPrompts)
	assert.Len(t, cfg.Rules.Paths, 3)
}

func TestLoad_FromFile(t *testing.T) {
	configDir := findProjectRoot(t)
	cfgPath := filepath.Join(configDir, "config.yaml")

	cfg, err := Load(cfgPath)
	require.NoError(t, err)
	assert.Equal(t, 0.5, cfg.Detector.Threshold)
	assert.Equal(t, ":8080", cfg.Proxy.Listen)
	assert.Equal(t, "https://api.openai.com", cfg.Proxy.Target)
	assert.Equal(t, 0.85, cfg.Detector.MLThreshold)
	assert.Equal(t, 0.6, cfg.Detector.Weights.Regex)
	assert.Equal(t, 0.4, cfg.Detector.Weights.ML)
}

func TestLoad_NoFile(t *testing.T) {
	cfg, err := Load("")
	require.NoError(t, err)
	assert.Equal(t, 0.5, cfg.Detector.Threshold) // should use defaults
}

func TestLoad_NonexistentFile(t *testing.T) {
	_, err := Load("/nonexistent/config.yaml")
	assert.Error(t, err)
}

func TestLoad_EnvOverride(t *testing.T) {
	t.Setenv("PIF_DETECTOR_THRESHOLD", "0.8")
	t.Setenv("PIF_PROXY_LISTEN", ":9090")

	cfg, err := Load("")
	require.NoError(t, err)
	assert.Equal(t, 0.8, cfg.Detector.Threshold)
	assert.Equal(t, ":9090", cfg.Proxy.Listen)
}

func TestLoad_MLEnvOverride(t *testing.T) {
	t.Setenv("PIF_DETECTOR_ML_MODEL_PATH", "/path/to/model")
	t.Setenv("PIF_DETECTOR_ML_THRESHOLD", "0.90")

	cfg, err := Load("")
	require.NoError(t, err)
	assert.Equal(t, "/path/to/model", cfg.Detector.MLModelPath)
	assert.Equal(t, 0.90, cfg.Detector.MLThreshold)
}

func TestLoad_CustomConfig(t *testing.T) {
	content := `
detector:
  threshold: 0.9
  min_severity: "high"
  timeout_ms: 20
proxy:
  listen: ":3000"
  target: "https://api.anthropic.com"
  action: "flag"
`
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "custom.yaml")
	err := os.WriteFile(cfgPath, []byte(content), 0644)
	require.NoError(t, err)

	cfg, err := Load(cfgPath)
	require.NoError(t, err)
	assert.Equal(t, 0.9, cfg.Detector.Threshold)
	assert.Equal(t, "high", cfg.Detector.MinSeverity)
	assert.Equal(t, 20, cfg.Detector.TimeoutMs)
	assert.Equal(t, ":3000", cfg.Proxy.Listen)
	assert.Equal(t, "https://api.anthropic.com", cfg.Proxy.Target)
	assert.Equal(t, "flag", cfg.Proxy.Action)
}

func findProjectRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	require.NoError(t, err)

	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find project root")
		}
		dir = parent
	}
}
