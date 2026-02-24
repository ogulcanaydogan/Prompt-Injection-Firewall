package rules

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"gopkg.in/yaml.v3"
)

// LoadFile loads a rule set from a YAML file.
func LoadFile(path string) (*RuleSet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading rule file %s: %w", path, err)
	}

	var rs RuleSet
	if err := yaml.Unmarshal(data, &rs); err != nil {
		return nil, fmt.Errorf("parsing rule file %s: %w", path, err)
	}

	if err := validate(&rs); err != nil {
		return nil, fmt.Errorf("validating rule file %s: %w", path, err)
	}

	return &rs, nil
}

// LoadDir loads all YAML rule files from a directory.
func LoadDir(dir string) ([]RuleSet, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading rules directory %s: %w", dir, err)
	}

	var sets []RuleSet
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ext := filepath.Ext(entry.Name())
		if ext != ".yaml" && ext != ".yml" {
			continue
		}
		rs, err := LoadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, err
		}
		sets = append(sets, *rs)
	}

	return sets, nil
}

// validate checks that all rules in a RuleSet have valid patterns and required fields.
func validate(rs *RuleSet) error {
	if rs.Name == "" {
		return fmt.Errorf("rule set name is required")
	}

	seen := make(map[string]bool)
	for i, r := range rs.Rules {
		if r.ID == "" {
			return fmt.Errorf("rule at index %d: id is required", i)
		}
		if seen[r.ID] {
			return fmt.Errorf("duplicate rule id: %s", r.ID)
		}
		seen[r.ID] = true

		if r.Pattern == "" {
			return fmt.Errorf("rule %s: pattern is required", r.ID)
		}
		if _, err := regexp.Compile(r.Pattern); err != nil {
			return fmt.Errorf("rule %s: invalid pattern: %w", r.ID, err)
		}
	}

	return nil
}

// MergeRuleSets combines multiple rule sets into a single slice of enabled rules.
func MergeRuleSets(sets []RuleSet) []Rule {
	var rules []Rule
	for _, rs := range sets {
		for _, r := range rs.Rules {
			if r.Enabled {
				rules = append(rules, r)
			}
		}
	}
	return rules
}
