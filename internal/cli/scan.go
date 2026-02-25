package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/ogulcanaydogan/Prompt-Injection-Firewall/pkg/detector"
	"github.com/ogulcanaydogan/Prompt-Injection-Firewall/pkg/rules"
)

var (
	scanFile      string
	scanStdin     bool
	scanOutput    string
	scanThreshold float64
	scanSeverity  string
	scanQuiet     bool
	scanVerbose   bool
	scanRules     []string
	scanModel     string
)

func newScanCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scan [prompt]",
		Short: "Scan a prompt for injection attacks",
		Long: `Scan a prompt text for prompt injection, jailbreak, data exfiltration,
and other attacks. Returns findings with severity and matched patterns.

Exit codes:
  0  Clean — no injection detected
  1  Injection detected
  2  Error`,
		Args: cobra.MaximumNArgs(1),
		RunE: runScan,
	}

	cmd.Flags().StringVarP(&scanFile, "file", "f", "", "read input from file")
	cmd.Flags().BoolVar(&scanStdin, "stdin", false, "read input from stdin")
	cmd.Flags().StringVarP(&scanOutput, "output", "o", "table", "output format: json, table")
	cmd.Flags().Float64Var(&scanThreshold, "threshold", 0.5, "score threshold for flagging (0.0-1.0)")
	cmd.Flags().StringVar(&scanSeverity, "severity", "low", "minimum severity: info, low, medium, high, critical")
	cmd.Flags().BoolVarP(&scanQuiet, "quiet", "q", false, "only output exit code")
	cmd.Flags().BoolVarP(&scanVerbose, "verbose", "v", false, "show detailed match information")
	cmd.Flags().StringSliceVarP(&scanRules, "rules", "r", nil, "additional rule files to load")
	cmd.Flags().StringVarP(&scanModel, "model", "m", "", "path to ONNX model directory or HuggingFace model ID")

	return cmd
}

func runScan(cmd *cobra.Command, args []string) error {
	text, err := getInputText(args)
	if err != nil {
		return err
	}

	if text == "" {
		return fmt.Errorf("no input provided; use an argument, --file, or --stdin")
	}

	d, err := buildDetector()
	if err != nil {
		return fmt.Errorf("building detector: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := d.Scan(ctx, detector.ScanInput{Text: text, Role: "user"})
	if err != nil {
		return fmt.Errorf("scanning: %w", err)
	}

	// Filter by severity
	minSev := detector.ParseSeverity(scanSeverity)
	filtered := filterBySeverity(result, minSev)

	if scanQuiet {
		if !filtered.Clean && filtered.Score >= scanThreshold {
			os.Exit(1)
		}
		return nil
	}

	switch scanOutput {
	case "json":
		return printJSON(cmd.OutOrStdout(), filtered)
	default:
		return printTable(cmd.OutOrStdout(), filtered, scanThreshold, scanVerbose)
	}
}

func getInputText(args []string) (string, error) {
	if scanStdin {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return "", fmt.Errorf("reading stdin: %w", err)
		}
		return string(data), nil
	}

	if scanFile != "" {
		data, err := os.ReadFile(scanFile)
		if err != nil {
			return "", fmt.Errorf("reading file %s: %w", scanFile, err)
		}
		return string(data), nil
	}

	if len(args) > 0 {
		return args[0], nil
	}

	return "", nil
}

func buildDetector() (detector.Detector, error) {
	// Load default rules
	rulePaths := []string{
		"rules/owasp-llm-top10.yaml",
		"rules/jailbreak-patterns.yaml",
		"rules/data-exfil.yaml",
	}

	// Try loading from the project directory first, then check common locations
	var sets []rules.RuleSet
	for _, p := range rulePaths {
		rs, err := rules.LoadFile(p)
		if err != nil {
			// Try with /etc/pif/ prefix (Docker)
			rs, err = rules.LoadFile("/etc/pif/" + p)
			if err != nil {
				continue
			}
		}
		sets = append(sets, *rs)
	}

	// Also load any additional rule files specified on the command line
	for _, p := range scanRules {
		rs, err := rules.LoadFile(p)
		if err != nil {
			return nil, fmt.Errorf("loading rule file %s: %w", p, err)
		}
		sets = append(sets, *rs)
	}

	if len(sets) == 0 {
		return nil, fmt.Errorf("no rule files found; ensure rules/ directory exists or specify --rules")
	}

	d, err := detector.NewRegexDetector(sets...)
	if err != nil {
		return nil, err
	}

	// Determine ensemble strategy and try to add ML detector
	modelPath := scanModel
	if modelPath == "" {
		modelPath = os.Getenv("PIF_DETECTOR_ML_MODEL_PATH")
	}

	if modelPath != "" {
		// Try to create ML detector — if built without ml tag, this returns ErrMLNotAvailable
		mlDet, mlErr := detector.NewMLDetector(detector.MLConfig{
			ModelPath: modelPath,
			Threshold: 0.85,
		})
		if mlErr == nil {
			// ML available: use weighted strategy with both detectors
			ensemble := detector.NewEnsemble(detector.StrategyWeighted, 100*time.Millisecond)
			ensemble.Register(d, 0.6)
			ensemble.Register(mlDet, 0.4)
			return ensemble, nil
		}
		// ML not available: log and fall back to regex-only
		fmt.Fprintf(os.Stderr, "Warning: ML detector unavailable (%v), using regex-only\n", mlErr)
	}

	// Regex-only: use AnyMatch strategy
	ensemble := detector.NewEnsemble(detector.StrategyAnyMatch, 100*time.Millisecond)
	ensemble.Register(d, 1.0)

	return ensemble, nil
}

func filterBySeverity(result *detector.ScanResult, minSev detector.Severity) *detector.ScanResult {
	var filtered []detector.Finding
	for _, f := range result.Findings {
		if f.Severity >= minSev {
			filtered = append(filtered, f)
		}
	}

	clean := len(filtered) == 0
	score := result.Score
	if clean {
		score = 0
	}

	return &detector.ScanResult{
		Clean:      clean,
		Score:      score,
		Findings:   filtered,
		DetectorID: result.DetectorID,
		Duration:   result.Duration,
		InputHash:  result.InputHash,
	}
}
