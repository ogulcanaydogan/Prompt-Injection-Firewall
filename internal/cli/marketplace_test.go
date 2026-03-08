package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMarketplaceCommandStructure(t *testing.T) {
	cmd := newMarketplaceCmd()
	subcommands := make(map[string]bool)
	for _, sub := range cmd.Commands() {
		subcommands[sub.Name()] = true
	}
	assert.True(t, subcommands["list"])
	assert.True(t, subcommands["install"])
	assert.True(t, subcommands["update"])
}

func TestMarketplaceList_Disabled(t *testing.T) {
	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, "config.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(`marketplace:
  enabled: false
`), 0644))

	origCfgFile := cfgFile
	defer func() { cfgFile = origCfgFile }()
	cfgFile = cfgPath

	cmd := newMarketplaceListCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "marketplace is disabled")
}

func TestMarketplaceCommands_EnabledFlow(t *testing.T) {
	tmp := t.TempDir()
	ruleBody := []byte(`name: "pack"
version: "1.0.0"
rules:
  - id: "PACK-1"
    name: "pack"
    description: "pack"
    category: "prompt_injection"
    severity: 2
    pattern: "pack_attack"
    enabled: true
    case_sensitive: false
`)
	rulePath := filepath.Join(tmp, "pack.yaml")
	require.NoError(t, os.WriteFile(rulePath, ruleBody, 0644))
	sum := sha256.Sum256(ruleBody)

	index := []map[string]interface{}{
		{
			"id":           "pack",
			"name":         "Pack",
			"version":      "1.0.0",
			"download_url": rulePath,
			"sha256":       hex.EncodeToString(sum[:]),
			"categories":   []string{"security"},
			"maintainer":   "community",
		},
	}
	indexPath := filepath.Join(tmp, "index.json")
	rawIndex, err := json.Marshal(index)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(indexPath, rawIndex, 0644))

	cfgPath := filepath.Join(tmp, "config.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(`
marketplace:
  enabled: true
  index_url: "`+indexPath+`"
  cache_dir: "`+filepath.Join(tmp, ".cache")+`"
  install_dir: "`+filepath.Join(tmp, "rules", "community")+`"
  require_checksum: true
`), 0644))

	origCfgFile := cfgFile
	defer func() { cfgFile = origCfgFile }()
	cfgFile = cfgPath

	listCmd := newMarketplaceListCmd()
	listOut := &bytes.Buffer{}
	listCmd.SetOut(listOut)
	listCmd.SetErr(listOut)
	require.NoError(t, listCmd.Execute())
	assert.Contains(t, listOut.String(), "pack")

	installCmd := newMarketplaceInstallCmd()
	installCmd.SetArgs([]string{"pack@1.0.0"})
	installOut := &bytes.Buffer{}
	installCmd.SetOut(installOut)
	installCmd.SetErr(installOut)
	require.NoError(t, installCmd.Execute())
	assert.Contains(t, installOut.String(), "Installed pack@1.0.0")
	assert.FileExists(t, filepath.Join(tmp, "rules", "community", "pack_1.0.0.yaml"))

	updateCmd := newMarketplaceUpdateCmd()
	updateOut := &bytes.Buffer{}
	updateCmd.SetOut(updateOut)
	updateCmd.SetErr(updateOut)
	require.NoError(t, updateCmd.Execute())
	assert.Contains(t, updateOut.String(), "summary:")
}
