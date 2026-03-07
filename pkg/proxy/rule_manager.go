package proxy

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/ogulcanaydogan/Prompt-Injection-Firewall/pkg/detector"
	"github.com/ogulcanaydogan/Prompt-Injection-Firewall/pkg/rules"
)

const defaultManagedCustomRulePath = "rules/dashboard-custom.yaml"

// DetectorFactory builds a detector instance from the provided merged rule sets.
type DetectorFactory func(ruleSets []rules.RuleSet) (detector.Detector, error)

// RuleManagerSnapshot is a JSON-friendly projection of runtime rule-manager state.
type RuleManagerSnapshot struct {
	RuleSets      []RuleSetInfo `json:"rule_sets"`
	TotalRuleSets int           `json:"total_rule_sets"`
	TotalRules    int           `json:"total_rules"`
	ManagedPath   string        `json:"managed_path"`
	ManagedRules  []rules.Rule  `json:"managed_rules"`
}

// RuleManager defines runtime rule CRUD and snapshot behavior.
type RuleManager interface {
	Snapshot() RuleManagerSnapshot
	CreateRule(rule rules.Rule) error
	UpdateRule(id string, rule rules.Rule) error
	DeleteRule(id string) error
	Detector() detector.Detector
	CurrentDetector() detector.Detector
}

// RuntimeRuleManagerOptions controls runtime rule manager initialization.
type RuntimeRuleManagerOptions struct {
	RulePaths         []string
	CustomPaths       []string
	ManagedCustomPath string
	DetectorFactory   DetectorFactory
}

// HotSwappableDetector forwards scan operations to a detector instance that can
// be swapped at runtime.
type HotSwappableDetector struct {
	mu      sync.RWMutex
	current detector.Detector
}

func NewHotSwappableDetector(initial detector.Detector) *HotSwappableDetector {
	return &HotSwappableDetector{current: initial}
}

func (h *HotSwappableDetector) Set(next detector.Detector) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.current = next
}

func (h *HotSwappableDetector) Current() detector.Detector {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.current
}

func (h *HotSwappableDetector) ID() string {
	if d := h.Current(); d != nil {
		return d.ID()
	}
	return "swappable"
}

func (h *HotSwappableDetector) Ready() bool {
	if d := h.Current(); d != nil {
		return d.Ready()
	}
	return false
}

func (h *HotSwappableDetector) Scan(ctx context.Context, input detector.ScanInput) (*detector.ScanResult, error) {
	d := h.Current()
	if d == nil {
		return nil, fmt.Errorf("detector not initialized")
	}
	return d.Scan(ctx, input)
}

// RuntimeRuleManager stores mutable custom rules and atomically swaps detector
// instances after successful rebuilds.
type RuntimeRuleManager struct {
	mu              sync.RWMutex
	detectorFactory DetectorFactory
	detectorHandle  *HotSwappableDetector
	rulePaths       []string
	customPaths     []string
	managedPath     string
	managedRuleSet  rules.RuleSet
	inventory       []RuleSetInfo
	totalRules      int
}

func NewRuntimeRuleManager(opts RuntimeRuleManagerOptions) (*RuntimeRuleManager, error) {
	if opts.DetectorFactory == nil {
		return nil, fmt.Errorf("detector factory is required")
	}

	managedPath := strings.TrimSpace(opts.ManagedCustomPath)
	if managedPath == "" && len(opts.CustomPaths) > 0 {
		managedPath = strings.TrimSpace(opts.CustomPaths[0])
	}
	if managedPath == "" {
		managedPath = defaultManagedCustomRulePath
	}

	customPaths := dedupeNonEmptyPaths(opts.CustomPaths)
	if !containsPath(customPaths, managedPath) {
		customPaths = append(customPaths, managedPath)
	}

	manager := &RuntimeRuleManager{
		detectorFactory: opts.DetectorFactory,
		detectorHandle:  NewHotSwappableDetector(nil),
		rulePaths:       dedupeNonEmptyPaths(opts.RulePaths),
		customPaths:     customPaths,
		managedPath:     managedPath,
		managedRuleSet:  defaultManagedRuleSet(),
	}

	if err := manager.bootstrap(); err != nil {
		return nil, err
	}

	return manager, nil
}

func (m *RuntimeRuleManager) bootstrap() error {
	rs, _, err := loadRuleSetWithFallback(m.managedPath)
	if err == nil {
		m.managedRuleSet = *rs
		ensureManagedRuleSetMetadata(&m.managedRuleSet)
	} else if !isNotExist(err) {
		return fmt.Errorf("loading managed custom rules %s: %w", m.managedPath, err)
	}

	sets, inventory, total, err := m.loadAllRuleSets(m.managedRuleSet)
	if err != nil {
		return err
	}

	d, err := m.detectorFactory(sets)
	if err != nil {
		return fmt.Errorf("building detector: %w", err)
	}

	m.detectorHandle.Set(d)
	m.inventory = inventory
	m.totalRules = total
	return nil
}

func (m *RuntimeRuleManager) Snapshot() RuleManagerSnapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return RuleManagerSnapshot{
		RuleSets:      cloneRuleSetInfoSlice(m.inventory),
		TotalRuleSets: len(m.inventory),
		TotalRules:    m.totalRules,
		ManagedPath:   m.managedPath,
		ManagedRules:  cloneRules(m.managedRuleSet.Rules),
	}
}

func (m *RuntimeRuleManager) Detector() detector.Detector {
	return m.detectorHandle
}

func (m *RuntimeRuleManager) CurrentDetector() detector.Detector {
	return m.detectorHandle.Current()
}

func (m *RuntimeRuleManager) CreateRule(rule rules.Rule) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	rule.ID = strings.TrimSpace(rule.ID)
	if err := validateRule(rule); err != nil {
		return err
	}
	if m.findRuleIndex(rule.ID) >= 0 {
		return fmt.Errorf("rule already exists: %s", rule.ID)
	}

	prev := cloneRuleSet(m.managedRuleSet)
	m.managedRuleSet.Rules = append(m.managedRuleSet.Rules, rule)
	return m.persistAndReload(prev)
}

func (m *RuntimeRuleManager) UpdateRule(id string, rule rules.Rule) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("rule id is required")
	}

	idx := m.findRuleIndex(id)
	if idx < 0 {
		return fmt.Errorf("rule not found: %s", id)
	}

	if strings.TrimSpace(rule.ID) != "" && strings.TrimSpace(rule.ID) != id {
		return fmt.Errorf("rule id mismatch: %s", id)
	}
	rule.ID = id
	if err := validateRule(rule); err != nil {
		return err
	}

	prev := cloneRuleSet(m.managedRuleSet)
	m.managedRuleSet.Rules[idx] = rule
	return m.persistAndReload(prev)
}

func (m *RuntimeRuleManager) DeleteRule(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("rule id is required")
	}

	idx := m.findRuleIndex(id)
	if idx < 0 {
		return fmt.Errorf("rule not found: %s", id)
	}

	prev := cloneRuleSet(m.managedRuleSet)
	m.managedRuleSet.Rules = append(m.managedRuleSet.Rules[:idx], m.managedRuleSet.Rules[idx+1:]...)
	return m.persistAndReload(prev)
}

func (m *RuntimeRuleManager) persistAndReload(previous rules.RuleSet) error {
	if err := writeRuleSetAtomic(m.managedPath, m.managedRuleSet); err != nil {
		m.managedRuleSet = previous
		return fmt.Errorf("writing managed rules: %w", err)
	}

	sets, inventory, total, err := m.loadAllRuleSets(m.managedRuleSet)
	if err != nil {
		m.managedRuleSet = previous
		_ = writeRuleSetAtomic(m.managedPath, previous)
		return fmt.Errorf("reloading rules: %w", err)
	}

	d, err := m.detectorFactory(sets)
	if err != nil {
		m.managedRuleSet = previous
		_ = writeRuleSetAtomic(m.managedPath, previous)
		return fmt.Errorf("rebuilding detector: %w", err)
	}

	m.detectorHandle.Set(d)
	m.inventory = inventory
	m.totalRules = total
	return nil
}

func (m *RuntimeRuleManager) loadAllRuleSets(managed rules.RuleSet) ([]rules.RuleSet, []RuleSetInfo, int, error) {
	paths := append([]string{}, m.rulePaths...)
	paths = append(paths, m.customPaths...)

	sets := make([]rules.RuleSet, 0, len(paths))
	inventory := make([]RuleSetInfo, 0, len(paths))
	totalEnabled := 0

	for _, p := range paths {
		if p == m.managedPath {
			managedCopy := cloneRuleSet(managed)
			ensureManagedRuleSetMetadata(&managedCopy)
			sets = append(sets, managedCopy)
			enabled := enabledRuleCount(managedCopy.Rules)
			inventory = append(inventory, RuleSetInfo{Name: managedCopy.Name, Version: managedCopy.Version, RuleCount: enabled})
			totalEnabled += enabled
			continue
		}

		rs, _, err := loadRuleSetWithFallback(p)
		if err != nil {
			if isNotExist(err) && containsPath(m.customPaths, p) {
				continue
			}
			return nil, nil, 0, fmt.Errorf("loading rule set %s: %w", p, err)
		}

		sets = append(sets, *rs)
		enabled := enabledRuleCount(rs.Rules)
		inventory = append(inventory, RuleSetInfo{Name: rs.Name, Version: rs.Version, RuleCount: enabled})
		totalEnabled += enabled
	}

	if len(sets) == 0 {
		return nil, nil, 0, fmt.Errorf("no rule sets available")
	}

	return sets, inventory, totalEnabled, nil
}

func (m *RuntimeRuleManager) findRuleIndex(id string) int {
	for i, r := range m.managedRuleSet.Rules {
		if r.ID == id {
			return i
		}
	}
	return -1
}

func loadRuleSetWithFallback(path string) (*rules.RuleSet, string, error) {
	candidates := []string{path}
	if !filepath.IsAbs(path) {
		candidates = append(candidates, filepath.Join("/etc/pif", path))
	}

	var lastErr error
	for _, candidate := range candidates {
		rs, err := rules.LoadFile(candidate)
		if err == nil {
			return rs, candidate, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("failed to load rule set: %s", path)
	}
	return nil, "", lastErr
}

func writeRuleSetAtomic(path string, rs rules.RuleSet) error {
	ensureManagedRuleSetMetadata(&rs)
	data, err := yaml.Marshal(rs)
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	tmp, err := os.CreateTemp(dir, ".pif-rules-*.yaml")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	return os.Rename(tmpName, path)
}

func validateRule(rule rules.Rule) error {
	if strings.TrimSpace(rule.ID) == "" {
		return fmt.Errorf("rule id is required")
	}
	if strings.TrimSpace(rule.Pattern) == "" {
		return fmt.Errorf("rule pattern is required")
	}
	if _, err := regexp.Compile(rule.Pattern); err != nil {
		return fmt.Errorf("invalid rule pattern: %w", err)
	}
	if rule.Severity < int(detector.SeverityInfo) || rule.Severity > int(detector.SeverityCritical) {
		return fmt.Errorf("invalid severity: %d", rule.Severity)
	}
	return nil
}

func isNotExist(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, os.ErrNotExist) {
		return true
	}
	var pathErr *os.PathError
	return errors.As(err, &pathErr) && errors.Is(pathErr.Err, os.ErrNotExist)
}

func enabledRuleCount(rs []rules.Rule) int {
	total := 0
	for _, r := range rs {
		if r.Enabled {
			total++
		}
	}
	return total
}

func cloneRuleSet(src rules.RuleSet) rules.RuleSet {
	cp := rules.RuleSet{
		Name:        src.Name,
		Version:     src.Version,
		Description: src.Description,
		Rules:       cloneRules(src.Rules),
	}
	return cp
}

func cloneRules(src []rules.Rule) []rules.Rule {
	if src == nil {
		return []rules.Rule{}
	}
	out := make([]rules.Rule, 0, len(src))
	for _, r := range src {
		cp := r
		if r.Tags != nil {
			cp.Tags = append([]string{}, r.Tags...)
		}
		if r.Metadata != nil {
			cp.Metadata = make(map[string]string, len(r.Metadata))
			for k, v := range r.Metadata {
				cp.Metadata[k] = v
			}
		}
		out = append(out, cp)
	}
	return out
}

func cloneRuleSetInfoSlice(src []RuleSetInfo) []RuleSetInfo {
	if src == nil {
		return []RuleSetInfo{}
	}
	out := make([]RuleSetInfo, len(src))
	copy(out, src)
	return out
}

func defaultManagedRuleSet() rules.RuleSet {
	return rules.RuleSet{
		Name:        "Dashboard Custom Rules",
		Version:     "1.0.0",
		Description: "Custom rules managed via dashboard",
		Rules:       []rules.Rule{},
	}
}

func ensureManagedRuleSetMetadata(rs *rules.RuleSet) {
	if rs.Name == "" {
		rs.Name = "Dashboard Custom Rules"
	}
	if rs.Version == "" {
		rs.Version = "1.0.0"
	}
	if rs.Description == "" {
		rs.Description = "Custom rules managed via dashboard"
	}
	if rs.Rules == nil {
		rs.Rules = []rules.Rule{}
	}
}

func dedupeNonEmptyPaths(paths []string) []string {
	out := make([]string, 0, len(paths))
	seen := make(map[string]struct{}, len(paths))
	for _, p := range paths {
		trimmed := strings.TrimSpace(p)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	return out
}

func containsPath(paths []string, target string) bool {
	for _, p := range paths {
		if p == target {
			return true
		}
	}
	return false
}
