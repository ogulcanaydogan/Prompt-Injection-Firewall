package cli

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ogulcanaydogan/Prompt-Injection-Firewall/pkg/config"
	"github.com/ogulcanaydogan/Prompt-Injection-Firewall/pkg/detector"
	"github.com/ogulcanaydogan/Prompt-Injection-Firewall/pkg/rules"
)

func TestResolveProxyModelPath_Priority(t *testing.T) {
	origProxyModel := proxyModel
	origScanModel := scanModel
	defer func() {
		proxyModel = origProxyModel
		scanModel = origScanModel
	}()

	cfg := config.Default()
	cfg.Detector.MLModelPath = "/cfg/model"

	proxyModel = "/cli/model"
	got := resolveProxyModelPath(cfg)
	assert.Equal(t, "/cli/model", got)
	assert.Equal(t, "/cli/model", scanModel)

	proxyModel = ""
	got = resolveProxyModelPath(cfg)
	assert.Equal(t, "/cfg/model", got)
	assert.Equal(t, "/cfg/model", scanModel)

	cfg.Detector.MLModelPath = ""
	got = resolveProxyModelPath(cfg)
	assert.Equal(t, "", got)
}

func TestBuildProxyDetectorFactory_RegexOnly(t *testing.T) {
	cfg := config.Default()
	cfg.Detector.Strategy = "any"
	cfg.Detector.TimeoutMs = 50

	factory := buildProxyDetectorFactory(cfg, "")
	ruleSets := []rules.RuleSet{
		{
			Name:    "test-rules",
			Version: "1.0.0",
			Rules: []rules.Rule{
				{
					ID:            "T-1",
					Name:          "test",
					Description:   "test rule",
					Category:      "prompt_injection",
					Severity:      int(detector.SeverityHigh),
					Pattern:       "hello_attack",
					Enabled:       true,
					CaseSensitive: false,
				},
			},
		},
	}

	d, err := factory(ruleSets)
	require.NoError(t, err)
	ens, ok := d.(*detector.EnsembleDetector)
	require.True(t, ok)
	assert.Equal(t, 1, ens.DetectorCount())

	res, err := d.Scan(testContext(t), detector.ScanInput{Text: "hello_attack"})
	require.NoError(t, err)
	assert.False(t, res.Clean)
}

func TestRunProxy_InvalidTimeouts(t *testing.T) {
	tmp := t.TempDir()
	cfgPathRead := filepath.Join(tmp, "bad-read.yaml")
	cfgPathWrite := filepath.Join(tmp, "bad-write.yaml")

	require.NoError(t, os.WriteFile(cfgPathRead, []byte(`
proxy:
  read_timeout: "bad"
`), 0644))
	require.NoError(t, os.WriteFile(cfgPathWrite, []byte(`
proxy:
  read_timeout: "10s"
  write_timeout: "bad"
`), 0644))

	origCfgFile := cfgFile
	origProxyTarget := proxyTarget
	origProxyListen := proxyListen
	origProxyAction := proxyAction
	origProxyModel := proxyModel
	origScanModel := scanModel
	defer func() {
		cfgFile = origCfgFile
		proxyTarget = origProxyTarget
		proxyListen = origProxyListen
		proxyAction = origProxyAction
		proxyModel = origProxyModel
		scanModel = origScanModel
	}()

	cmd := newProxyCmd()

	cfgFile = cfgPathRead
	err := runProxy(cmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parsing proxy.read_timeout")

	cfgFile = cfgPathWrite
	err = runProxy(cmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parsing proxy.write_timeout")
}

func testContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	t.Cleanup(cancel)
	return ctx
}
