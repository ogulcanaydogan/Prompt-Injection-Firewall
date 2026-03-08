package proxy

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ogulcanaydogan/Prompt-Injection-Firewall/pkg/detector"
	"github.com/ogulcanaydogan/Prompt-Injection-Firewall/pkg/rules"
)

func TestRuntimeRuleManager_CRUDAndHotReload(t *testing.T) {
	tmp := t.TempDir()
	baseRulesPath := filepath.Join(tmp, "base.yaml")
	managedPath := filepath.Join(tmp, "custom.yaml")

	writeRuleSetFixture(t, baseRulesPath, rules.RuleSet{
		Name:    "base",
		Version: "1.0.0",
		Rules: []rules.Rule{
			{
				ID:            "BASE-001",
				Name:          "base",
				Description:   "base rule",
				Category:      "prompt_injection",
				Severity:      int(detector.SeverityMedium),
				Pattern:       "base_attack",
				Enabled:       true,
				CaseSensitive: false,
			},
		},
	})

	manager, err := NewRuntimeRuleManager(RuntimeRuleManagerOptions{
		RulePaths:       []string{baseRulesPath},
		CustomPaths:     []string{managedPath},
		DetectorFactory: testRuleManagerDetectorFactory,
	})
	require.NoError(t, err)

	snap := manager.Snapshot()
	assert.Equal(t, 2, snap.TotalRuleSets)
	assert.Equal(t, 1, snap.TotalRules)
	assert.Equal(t, 0, len(snap.ManagedRules))

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	before, err := manager.Detector().Scan(ctx, detector.ScanInput{Text: "contains custom_attack"})
	require.NoError(t, err)
	assert.True(t, before.Clean)

	err = manager.CreateRule(rules.Rule{
		ID:            "CUSTOM-001",
		Name:          "custom",
		Description:   "custom rule",
		Category:      "prompt_injection",
		Severity:      int(detector.SeverityHigh),
		Pattern:       "custom_attack",
		Enabled:       true,
		CaseSensitive: false,
	})
	require.NoError(t, err)

	afterCreate, err := manager.Detector().Scan(ctx, detector.ScanInput{Text: "contains custom_attack"})
	require.NoError(t, err)
	assert.False(t, afterCreate.Clean)
	require.NotEmpty(t, afterCreate.Findings)
	assert.Equal(t, "CUSTOM-001", afterCreate.Findings[0].RuleID)

	err = manager.UpdateRule("CUSTOM-001", rules.Rule{
		Name:          "custom-updated",
		Description:   "custom rule updated",
		Category:      "prompt_injection",
		Severity:      int(detector.SeverityHigh),
		Pattern:       "custom_attack_v2",
		Enabled:       true,
		CaseSensitive: false,
	})
	require.NoError(t, err)

	afterUpdateOldPattern, err := manager.Detector().Scan(ctx, detector.ScanInput{Text: "contains custom_attack"})
	require.NoError(t, err)
	assert.True(t, afterUpdateOldPattern.Clean)

	afterUpdateNewPattern, err := manager.Detector().Scan(ctx, detector.ScanInput{Text: "contains custom_attack_v2"})
	require.NoError(t, err)
	assert.False(t, afterUpdateNewPattern.Clean)

	err = manager.DeleteRule("CUSTOM-001")
	require.NoError(t, err)

	afterDelete, err := manager.Detector().Scan(ctx, detector.ScanInput{Text: "contains custom_attack_v2"})
	require.NoError(t, err)
	assert.True(t, afterDelete.Clean)

	if _, err := os.Stat(managedPath); err != nil {
		t.Fatalf("expected managed rule file to exist: %v", err)
	}
}

func TestRuntimeRuleManager_InvalidRuleRejected(t *testing.T) {
	tmp := t.TempDir()
	baseRulesPath := filepath.Join(tmp, "base.yaml")
	managedPath := filepath.Join(tmp, "custom.yaml")

	writeRuleSetFixture(t, baseRulesPath, rules.RuleSet{
		Name:    "base",
		Version: "1.0.0",
		Rules: []rules.Rule{
			{
				ID:            "BASE-001",
				Name:          "base",
				Description:   "base rule",
				Category:      "prompt_injection",
				Severity:      int(detector.SeverityMedium),
				Pattern:       "base_attack",
				Enabled:       true,
				CaseSensitive: false,
			},
		},
	})

	manager, err := NewRuntimeRuleManager(RuntimeRuleManagerOptions{
		RulePaths:       []string{baseRulesPath},
		CustomPaths:     []string{managedPath},
		DetectorFactory: testRuleManagerDetectorFactory,
	})
	require.NoError(t, err)

	err = manager.CreateRule(rules.Rule{
		ID:            "BROKEN-001",
		Name:          "broken",
		Description:   "broken rule",
		Category:      "prompt_injection",
		Severity:      int(detector.SeverityMedium),
		Pattern:       "(",
		Enabled:       true,
		CaseSensitive: false,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid rule pattern")

	snapshot := manager.Snapshot()
	assert.Equal(t, 0, len(snapshot.ManagedRules))
	assert.Equal(t, 1, snapshot.TotalRules)
}

func TestRuntimeRuleManager_DefaultManagedPathWhenCustomEmpty(t *testing.T) {
	tmp := t.TempDir()
	baseRulesPath := filepath.Join(tmp, "base.yaml")

	writeRuleSetFixture(t, baseRulesPath, rules.RuleSet{
		Name:    "base",
		Version: "1.0.0",
		Rules: []rules.Rule{
			{
				ID:            "BASE-001",
				Name:          "base",
				Description:   "base rule",
				Category:      "prompt_injection",
				Severity:      int(detector.SeverityMedium),
				Pattern:       "base_attack",
				Enabled:       true,
				CaseSensitive: false,
			},
		},
	})

	manager, err := NewRuntimeRuleManager(RuntimeRuleManagerOptions{
		RulePaths:       []string{baseRulesPath},
		CustomPaths:     []string{},
		DetectorFactory: testRuleManagerDetectorFactory,
	})
	require.NoError(t, err)

	snapshot := manager.Snapshot()
	assert.Equal(t, defaultManagedCustomRulePath, snapshot.ManagedPath)
	assert.Equal(t, 2, snapshot.TotalRuleSets)
}

func TestRuntimeRuleManager_LoadsMarketplaceDirectoryWithMetadata(t *testing.T) {
	tmp := t.TempDir()
	baseRulesPath := filepath.Join(tmp, "base.yaml")
	marketDir := filepath.Join(tmp, "rules", "community")
	managedPath := filepath.Join(tmp, "custom.yaml")

	writeRuleSetFixture(t, baseRulesPath, rules.RuleSet{
		Name:    "base",
		Version: "1.0.0",
		Rules: []rules.Rule{
			{
				ID:            "BASE-001",
				Name:          "base rule",
				Description:   "base rule",
				Category:      "prompt_injection",
				Severity:      int(detector.SeverityMedium),
				Pattern:       "base_hit",
				Enabled:       true,
				CaseSensitive: false,
			},
		},
	})

	marketFile := filepath.Join(marketDir, "community-pack_1.2.3.yaml")
	writeRuleSetFixture(t, marketFile, rules.RuleSet{
		Name:    "community-pack",
		Version: "1.2.3",
		Rules: []rules.Rule{
			{
				ID:            "COMM-001",
				Name:          "community",
				Description:   "community rule",
				Category:      "prompt_injection",
				Severity:      int(detector.SeverityHigh),
				Pattern:       "market_hit",
				Enabled:       true,
				CaseSensitive: false,
			},
		},
	})

	manager, err := NewRuntimeRuleManager(RuntimeRuleManagerOptions{
		RulePaths:             []string{baseRulesPath},
		CustomPaths:           []string{managedPath, marketDir},
		MarketplaceInstallDir: marketDir,
		DetectorFactory:       testRuleManagerDetectorFactory,
	})
	require.NoError(t, err)

	snapshot := manager.Snapshot()
	assert.GreaterOrEqual(t, snapshot.TotalRuleSets, 3)
	assert.GreaterOrEqual(t, snapshot.TotalRules, 2)

	var foundMarketplace bool
	for _, rs := range snapshot.RuleSets {
		if rs.Source == "marketplace" {
			foundMarketplace = true
			assert.NotEmpty(t, rs.Path)
			assert.Equal(t, "community-pack", rs.Name)
			require.NotNil(t, rs.Metadata)
			assert.Equal(t, "community-pack", rs.Metadata["id"])
			assert.Equal(t, "1.2.3", rs.Metadata["version"])
		}
	}
	assert.True(t, foundMarketplace)
}

func testRuleManagerDetectorFactory(ruleSets []rules.RuleSet) (detector.Detector, error) {
	regexDetector, err := detector.NewRegexDetector(ruleSets...)
	if err != nil {
		return nil, err
	}
	ensemble := detector.NewEnsemble(detector.StrategyAnyMatch, 80*time.Millisecond)
	ensemble.Register(regexDetector, 1.0)
	return ensemble, nil
}

func writeRuleSetFixture(t *testing.T, path string, rs rules.RuleSet) {
	t.Helper()
	err := os.MkdirAll(filepath.Dir(path), 0755)
	require.NoError(t, err)
	err = writeRuleSetAtomic(path, rs)
	require.NoError(t, err)
}
