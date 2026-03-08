package marketplace

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/ogulcanaydogan/Prompt-Injection-Firewall/pkg/rules"
)

const defaultHTTPTimeout = 10 * time.Second

// Config controls marketplace catalog and install behavior.
type Config struct {
	Enabled                bool
	IndexURL               string
	CacheDir               string
	InstallDir             string
	RefreshIntervalMinutes int
	RequireChecksum        bool
}

// Entry defines the catalog contract for a community rule package.
type Entry struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	DownloadURL string   `json:"download_url"`
	SHA256      string   `json:"sha256"`
	Categories  []string `json:"categories"`
	Maintainer  string   `json:"maintainer"`
}

type indexEnvelope struct {
	Items []Entry `json:"items"`
	Rules []Entry `json:"rules"`
}

// InstalledRule reports details about a completed install.
type InstalledRule struct {
	Entry    Entry
	FilePath string
}

// UpdateResult reports marketplace update outcomes.
type UpdateResult struct {
	Updated []InstalledRule
	Skipped []string
}

// List returns the current marketplace catalog.
func List(ctx context.Context, cfg Config) ([]Entry, error) {
	items, err := loadIndex(ctx, cfg)
	if err != nil {
		return nil, err
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].ID == items[j].ID {
			return compareVersions(items[i].Version, items[j].Version) > 0
		}
		return items[i].ID < items[j].ID
	})
	return items, nil
}

// Install installs a specific marketplace rule package in <id>@<version> form.
func Install(ctx context.Context, cfg Config, selector string) (*InstalledRule, error) {
	id, version, err := parseSelector(selector)
	if err != nil {
		return nil, err
	}
	items, err := loadIndex(ctx, cfg)
	if err != nil {
		return nil, err
	}
	entry, err := findEntry(items, id, version)
	if err != nil {
		return nil, err
	}
	return installEntry(ctx, cfg, entry)
}

// Update installs newer versions of already-installed marketplace packages.
func Update(ctx context.Context, cfg Config) (*UpdateResult, error) {
	items, err := loadIndex(ctx, cfg)
	if err != nil {
		return nil, err
	}
	installed, err := listInstalled(cfg.InstallDir)
	if err != nil {
		if os.IsNotExist(err) {
			return &UpdateResult{}, nil
		}
		return nil, err
	}

	latest := make(map[string]Entry)
	for _, item := range items {
		current, ok := latest[item.ID]
		if !ok || compareVersions(item.Version, current.Version) > 0 {
			latest[item.ID] = item
		}
	}

	result := &UpdateResult{}
	for id, version := range installed {
		candidate, ok := latest[id]
		if !ok {
			result.Skipped = append(result.Skipped, id+"@"+version)
			continue
		}
		if compareVersions(candidate.Version, version) <= 0 {
			result.Skipped = append(result.Skipped, id+"@"+version)
			continue
		}
		installedRule, err := installEntry(ctx, cfg, candidate)
		if err != nil {
			return nil, err
		}
		result.Updated = append(result.Updated, *installedRule)
	}

	sort.Strings(result.Skipped)
	return result, nil
}

func installEntry(ctx context.Context, cfg Config, entry Entry) (*InstalledRule, error) {
	if strings.TrimSpace(cfg.InstallDir) == "" {
		return nil, fmt.Errorf("marketplace.install_dir is required")
	}
	body, err := readFromLocation(ctx, entry.DownloadURL)
	if err != nil {
		return nil, fmt.Errorf("downloading %s@%s: %w", entry.ID, entry.Version, err)
	}
	if cfg.RequireChecksum {
		if err := verifyChecksum(body, entry.SHA256); err != nil {
			return nil, err
		}
	}
	if err := validateRuleYAML(body); err != nil {
		return nil, err
	}

	if err := os.MkdirAll(cfg.InstallDir, 0755); err != nil {
		return nil, err
	}
	filename := fmt.Sprintf("%s_%s.yaml", sanitizeFilePart(entry.ID), sanitizeFilePart(entry.Version))
	target := filepath.Join(cfg.InstallDir, filename)
	if err := os.WriteFile(target, body, 0644); err != nil {
		return nil, err
	}

	if cacheDir := strings.TrimSpace(cfg.CacheDir); cacheDir != "" {
		_ = os.MkdirAll(cacheDir, 0755)
		cachePath := filepath.Join(cacheDir, "last-installed.json")
		_ = os.WriteFile(cachePath, bodyOrEmptyJSON(entry), 0644)
	}

	return &InstalledRule{Entry: entry, FilePath: target}, nil
}

func bodyOrEmptyJSON(entry Entry) []byte {
	b, err := json.Marshal(entry)
	if err != nil {
		return []byte("{}")
	}
	return b
}

func loadIndex(ctx context.Context, cfg Config) ([]Entry, error) {
	if strings.TrimSpace(cfg.IndexURL) == "" {
		return nil, fmt.Errorf("marketplace.index_url is required")
	}
	body, err := readFromLocation(ctx, cfg.IndexURL)
	if err != nil {
		return nil, err
	}

	var asList []Entry
	if err := json.Unmarshal(body, &asList); err == nil {
		return validateEntries(asList)
	}

	var env indexEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, fmt.Errorf("parsing marketplace index: %w", err)
	}
	if len(env.Items) > 0 {
		return validateEntries(env.Items)
	}
	return validateEntries(env.Rules)
}

func validateEntries(items []Entry) ([]Entry, error) {
	if len(items) == 0 {
		return nil, fmt.Errorf("marketplace index has no entries")
	}
	seen := make(map[string]struct{}, len(items))
	out := make([]Entry, 0, len(items))
	for _, item := range items {
		item.ID = strings.TrimSpace(item.ID)
		item.Version = strings.TrimSpace(item.Version)
		item.DownloadURL = strings.TrimSpace(item.DownloadURL)
		item.SHA256 = strings.ToLower(strings.TrimSpace(item.SHA256))
		if item.ID == "" || item.Version == "" || item.DownloadURL == "" {
			return nil, fmt.Errorf("invalid marketplace entry: id/version/download_url are required")
		}
		key := item.ID + "@" + item.Version
		if _, ok := seen[key]; ok {
			return nil, fmt.Errorf("duplicate marketplace entry: %s", key)
		}
		seen[key] = struct{}{}
		out = append(out, item)
	}
	return out, nil
}

func parseSelector(selector string) (string, string, error) {
	selector = strings.TrimSpace(selector)
	parts := strings.Split(selector, "@")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("selector must be in <id>@<version> format")
	}
	id := strings.TrimSpace(parts[0])
	version := strings.TrimSpace(parts[1])
	if id == "" || version == "" {
		return "", "", fmt.Errorf("selector must be in <id>@<version> format")
	}
	return id, version, nil
}

func findEntry(items []Entry, id, version string) (Entry, error) {
	for _, item := range items {
		if item.ID == id && item.Version == version {
			return item, nil
		}
	}
	return Entry{}, fmt.Errorf("marketplace package not found: %s@%s", id, version)
}

func readFromLocation(ctx context.Context, location string) ([]byte, error) {
	location = strings.TrimSpace(location)
	if location == "" {
		return nil, fmt.Errorf("location is required")
	}

	u, err := url.Parse(location)
	if err == nil {
		switch strings.ToLower(u.Scheme) {
		case "http", "https":
			client := &http.Client{Timeout: defaultHTTPTimeout}
			req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, location, nil)
			if reqErr != nil {
				return nil, reqErr
			}
			resp, reqErr := client.Do(req)
			if reqErr != nil {
				return nil, reqErr
			}
			defer resp.Body.Close()
			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
			}
			return io.ReadAll(io.LimitReader(resp.Body, 20*1024*1024))
		case "file":
			return os.ReadFile(u.Path)
		}
	}
	return os.ReadFile(location)
}

func verifyChecksum(body []byte, expected string) error {
	expected = strings.ToLower(strings.TrimSpace(expected))
	if expected == "" {
		return fmt.Errorf("marketplace entry missing sha256 checksum")
	}
	sum := sha256.Sum256(body)
	actual := hex.EncodeToString(sum[:])
	if actual != expected {
		return fmt.Errorf("checksum mismatch: expected %s got %s", expected, actual)
	}
	return nil
}

func validateRuleYAML(body []byte) error {
	var rs rules.RuleSet
	if err := yaml.Unmarshal(body, &rs); err != nil {
		return fmt.Errorf("invalid rule yaml: %w", err)
	}
	if rs.Name == "" {
		return fmt.Errorf("invalid rule yaml: rule set name is required")
	}
	for idx, rule := range rs.Rules {
		if strings.TrimSpace(rule.ID) == "" || strings.TrimSpace(rule.Pattern) == "" {
			return fmt.Errorf("invalid rule yaml: rule %d missing id or pattern", idx)
		}
	}
	return nil
}

func listInstalled(installDir string) (map[string]string, error) {
	entries, err := os.ReadDir(installDir)
	if err != nil {
		return nil, err
	}
	installed := make(map[string]string)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := strings.ToLower(entry.Name())
		if !(strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml")) {
			continue
		}
		id, version, err := parseInstalledFile(entry.Name())
		if err != nil {
			continue
		}
		installed[id] = version
	}
	return installed, nil
}

func parseInstalledFile(filename string) (string, string, error) {
	base := strings.TrimSuffix(strings.TrimSuffix(filename, ".yaml"), ".yml")
	idx := strings.LastIndex(base, "_")
	if idx <= 0 || idx >= len(base)-1 {
		return "", "", fmt.Errorf("invalid installed filename")
	}
	return base[:idx], base[idx+1:], nil
}

func sanitizeFilePart(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "unknown"
	}
	builder := strings.Builder{}
	for _, ch := range value {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' || ch == '.' {
			builder.WriteRune(ch)
			continue
		}
		builder.WriteRune('_')
	}
	return builder.String()
}

func compareVersions(a, b string) int {
	if a == b {
		return 0
	}
	ap := splitVersion(a)
	bp := splitVersion(b)
	max := len(ap)
	if len(bp) > max {
		max = len(bp)
	}
	for i := 0; i < max; i++ {
		av := partAt(ap, i)
		bv := partAt(bp, i)
		ai, aErr := strconv.Atoi(av)
		bi, bErr := strconv.Atoi(bv)
		if aErr == nil && bErr == nil {
			if ai == bi {
				continue
			}
			if ai > bi {
				return 1
			}
			return -1
		}
		if av == bv {
			continue
		}
		if av > bv {
			return 1
		}
		return -1
	}
	return 0
}

func splitVersion(version string) []string {
	version = strings.TrimPrefix(strings.TrimSpace(version), "v")
	if version == "" {
		return []string{"0"}
	}
	return strings.Split(version, ".")
}

func partAt(parts []string, idx int) string {
	if idx >= len(parts) {
		return "0"
	}
	return parts[idx]
}
