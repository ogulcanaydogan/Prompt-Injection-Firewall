package detector

import "time"

// Severity levels for detected threats.
type Severity int

const (
	SeverityInfo     Severity = 0
	SeverityLow      Severity = 1
	SeverityMedium   Severity = 2
	SeverityHigh     Severity = 3
	SeverityCritical Severity = 4
)

// String returns the string representation of a Severity level.
func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "info"
	case SeverityLow:
		return "low"
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// ParseSeverity converts a string to a Severity level.
func ParseSeverity(s string) Severity {
	switch s {
	case "info":
		return SeverityInfo
	case "low":
		return SeverityLow
	case "medium":
		return SeverityMedium
	case "high":
		return SeverityHigh
	case "critical":
		return SeverityCritical
	default:
		return SeverityInfo
	}
}

// Category classifies the type of injection attack.
type Category string

const (
	CategoryPromptInjection    Category = "prompt_injection"
	CategoryJailbreak          Category = "jailbreak"
	CategoryRoleHijack         Category = "role_hijack"
	CategoryDataExfiltration   Category = "data_exfiltration"
	CategorySystemPromptLeak   Category = "system_prompt_leak"
	CategoryEncodingAttack     Category = "encoding_attack"
	CategoryOutputManipulation Category = "output_manipulation"
	CategoryDenialOfService    Category = "denial_of_service"
	CategoryContextInjection   Category = "context_injection"
	CategoryMultiTurn          Category = "multi_turn_manipulation"
)

// Finding represents a single detected issue within a prompt.
type Finding struct {
	RuleID      string            `json:"rule_id"`
	Category    Category          `json:"category"`
	Severity    Severity          `json:"severity"`
	Description string            `json:"description"`
	MatchedText string            `json:"matched_text"`
	Offset      int               `json:"offset"`
	Length      int               `json:"length"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// ScanResult is the output of a detection scan.
type ScanResult struct {
	Clean      bool          `json:"clean"`
	Score      float64       `json:"score"`
	Findings   []Finding     `json:"findings"`
	DetectorID string        `json:"detector_id"`
	Duration   time.Duration `json:"duration_ns"`
	InputHash  string        `json:"input_hash"`
}

// ScanInput wraps the text to be scanned with optional context.
type ScanInput struct {
	Text     string            `json:"text"`
	Role     string            `json:"role"`
	Metadata map[string]string `json:"metadata,omitempty"`
}
