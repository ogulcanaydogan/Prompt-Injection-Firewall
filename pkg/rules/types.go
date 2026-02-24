package rules

// Rule defines a single detection rule.
type Rule struct {
	ID            string            `yaml:"id" json:"id"`
	Name          string            `yaml:"name" json:"name"`
	Description   string            `yaml:"description" json:"description"`
	Category      string            `yaml:"category" json:"category"`
	Severity      int               `yaml:"severity" json:"severity"`
	Pattern       string            `yaml:"pattern" json:"pattern"`
	Enabled       bool              `yaml:"enabled" json:"enabled"`
	Tags          []string          `yaml:"tags,omitempty" json:"tags,omitempty"`
	CaseSensitive bool              `yaml:"case_sensitive" json:"case_sensitive"`
	Metadata      map[string]string `yaml:"metadata,omitempty" json:"metadata,omitempty"`
}

// RuleSet is a named collection of rules loaded from a YAML file.
type RuleSet struct {
	Name        string `yaml:"name" json:"name"`
	Version     string `yaml:"version" json:"version"`
	Description string `yaml:"description" json:"description"`
	Rules       []Rule `yaml:"rules" json:"rules"`
}
