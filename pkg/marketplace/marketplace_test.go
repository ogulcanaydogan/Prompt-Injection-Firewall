package marketplace

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestListAndInstall(t *testing.T) {
	tmp := t.TempDir()
	rulePath := filepath.Join(tmp, "community-rule.yaml")
	ruleBody := []byte(`name: "Community Rules"
version: "1.0.0"
description: "test"
rules:
  - id: "COMM-001"
    name: "community"
    description: "detect"
    category: "prompt_injection"
    severity: 2
    pattern: "community_attack"
    enabled: true
    case_sensitive: false
`)
	require.NoError(t, os.WriteFile(rulePath, ruleBody, 0644))

	sum := sha256.Sum256(ruleBody)
	index := []Entry{
		{
			ID:          "community-rule",
			Name:        "Community Rule",
			Version:     "1.0.0",
			DownloadURL: rulePath,
			SHA256:      hex.EncodeToString(sum[:]),
			Maintainer:  "pif-community",
		},
	}
	indexPath := filepath.Join(tmp, "index.json")
	payload, err := json.Marshal(index)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(indexPath, payload, 0644))

	cfg := Config{
		Enabled:         true,
		IndexURL:        indexPath,
		InstallDir:      filepath.Join(tmp, "rules", "community"),
		CacheDir:        filepath.Join(tmp, ".cache"),
		RequireChecksum: true,
	}

	items, err := List(context.Background(), cfg)
	require.NoError(t, err)
	require.Len(t, items, 1)
	assert.Equal(t, "community-rule", items[0].ID)

	installed, err := Install(context.Background(), cfg, "community-rule@1.0.0")
	require.NoError(t, err)
	assert.FileExists(t, installed.FilePath)
	assert.Contains(t, filepath.Base(installed.FilePath), "community-rule_1.0.0")
}

func TestInstallChecksumMismatch(t *testing.T) {
	tmp := t.TempDir()
	rulePath := filepath.Join(tmp, "rule.yaml")
	require.NoError(t, os.WriteFile(rulePath, []byte(`name: "x"
version: "1.0.0"
rules:
  - id: "X"
    name: "x"
    description: "x"
    category: "prompt_injection"
    severity: 2
    pattern: "x"
    enabled: true
    case_sensitive: false
`), 0644))

	index := []Entry{
		{
			ID:          "x",
			Name:        "x",
			Version:     "1.0.0",
			DownloadURL: rulePath,
			SHA256:      "deadbeef",
		},
	}
	indexPath := filepath.Join(tmp, "index.json")
	payload, err := json.Marshal(index)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(indexPath, payload, 0644))

	cfg := Config{IndexURL: indexPath, InstallDir: filepath.Join(tmp, "rules"), RequireChecksum: true}
	_, err = Install(context.Background(), cfg, "x@1.0.0")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "checksum mismatch")
}

func TestUpdateInstallsNewerVersion(t *testing.T) {
	tmp := t.TempDir()
	installDir := filepath.Join(tmp, "rules", "community")
	require.NoError(t, os.MkdirAll(installDir, 0755))

	oldRule := []byte(`name: "pack"
version: "1.0.0"
rules:
  - id: "PACK-1"
    name: "pack"
    description: "pack"
    category: "prompt_injection"
    severity: 2
    pattern: "pack_v1"
    enabled: true
    case_sensitive: false
`)
	newRule := []byte(`name: "pack"
version: "1.1.0"
rules:
  - id: "PACK-1"
    name: "pack"
    description: "pack"
    category: "prompt_injection"
    severity: 2
    pattern: "pack_v2"
    enabled: true
    case_sensitive: false
`)
	oldPath := filepath.Join(tmp, "pack-v1.yaml")
	newPath := filepath.Join(tmp, "pack-v2.yaml")
	require.NoError(t, os.WriteFile(oldPath, oldRule, 0644))
	require.NoError(t, os.WriteFile(newPath, newRule, 0644))

	sumOld := sha256.Sum256(oldRule)
	sumNew := sha256.Sum256(newRule)

	entries := []Entry{
		{ID: "pack", Name: "pack", Version: "1.0.0", DownloadURL: oldPath, SHA256: hex.EncodeToString(sumOld[:])},
		{ID: "pack", Name: "pack", Version: "1.1.0", DownloadURL: newPath, SHA256: hex.EncodeToString(sumNew[:])},
	}
	indexPath := filepath.Join(tmp, "index.json")
	payload, err := json.Marshal(entries)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(indexPath, payload, 0644))

	require.NoError(t, os.WriteFile(filepath.Join(installDir, "pack_1.0.0.yaml"), oldRule, 0644))

	cfg := Config{IndexURL: indexPath, InstallDir: installDir, RequireChecksum: true}
	result, err := Update(context.Background(), cfg)
	require.NoError(t, err)
	require.Len(t, result.Updated, 1)
	assert.Equal(t, "1.1.0", result.Updated[0].Entry.Version)
	assert.FileExists(t, filepath.Join(installDir, "pack_1.1.0.yaml"))
}

func TestList_LoadsEnvelopeAndHTTPSource(t *testing.T) {
	ruleBody := []byte(`name: "http-pack"
version: "1.0.0"
rules:
  - id: "HTTP-1"
    name: "http"
    description: "http"
    category: "prompt_injection"
    severity: 2
    pattern: "http_attack"
    enabled: true
    case_sensitive: false
`)
	sum := sha256.Sum256(ruleBody)

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/index.json":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"items": []map[string]interface{}{
					{
						"id":           "http-pack",
						"name":         "HTTP Pack",
						"version":      "1.0.0",
						"download_url": server.URL + "/rule.yaml",
						"sha256":       hex.EncodeToString(sum[:]),
						"maintainer":   "community",
					},
				},
			})
		case "/rule.yaml":
			_, _ = w.Write(ruleBody)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	cfg := Config{
		IndexURL:        server.URL + "/index.json",
		InstallDir:      filepath.Join(t.TempDir(), "rules"),
		RequireChecksum: true,
	}

	items, err := List(context.Background(), cfg)
	require.NoError(t, err)
	require.Len(t, items, 1)
	assert.Equal(t, "http-pack", items[0].ID)

	installed, err := Install(context.Background(), cfg, "http-pack@1.0.0")
	require.NoError(t, err)
	assert.FileExists(t, installed.FilePath)
}

func TestInstall_InvalidSelector(t *testing.T) {
	_, err := Install(context.Background(), Config{IndexURL: "dummy", InstallDir: "tmp"}, "invalid-selector")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "<id>@<version>")
}
