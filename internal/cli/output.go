package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/ogulcanaydogan/Prompt-Injection-Firewall/pkg/detector"
)

func printJSON(w io.Writer, result *detector.ScanResult) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")

	output := map[string]interface{}{
		"clean":       result.Clean,
		"score":       result.Score,
		"findings":    result.Findings,
		"detector_id": result.DetectorID,
		"duration_ms": float64(result.Duration.Microseconds()) / 1000.0,
		"input_hash":  result.InputHash,
	}

	return enc.Encode(output)
}

func printTable(w io.Writer, result *detector.ScanResult, threshold float64, verbose bool) error {
	if result.Clean || result.Score < threshold {
		fmt.Fprintf(w, "RESULT: CLEAN (score: %.2f)\n", result.Score)
		fmt.Fprintf(w, "\nScanned in %.2fms\n", float64(result.Duration.Microseconds())/1000.0)
		return nil
	}

	fmt.Fprintf(w, "RESULT: INJECTION DETECTED (score: %.2f)\n\n", result.Score)

	// Header
	fmt.Fprintf(w, "  %-16s %-24s %-10s %s\n", "RULE ID", "CATEGORY", "SEVERITY", "MATCH")
	fmt.Fprintf(w, "  %s %s %s %s\n",
		strings.Repeat("-", 16),
		strings.Repeat("-", 24),
		strings.Repeat("-", 10),
		strings.Repeat("-", 40),
	)

	for _, f := range result.Findings {
		matched := f.MatchedText
		if len(matched) > 50 {
			matched = matched[:50] + "..."
		}
		matched = fmt.Sprintf("%q", matched)

		fmt.Fprintf(w, "  %-16s %-24s %-10s %s\n",
			f.RuleID,
			string(f.Category),
			f.Severity.String(),
			matched,
		)

		if verbose {
			fmt.Fprintf(w, "    Description: %s\n", f.Description)
			fmt.Fprintf(w, "    Offset: %d, Length: %d\n\n", f.Offset, f.Length)
		}
	}

	fmt.Fprintf(w, "\n%d finding(s) in %.2fms\n",
		len(result.Findings),
		float64(result.Duration.Microseconds())/1000.0,
	)

	return nil
}
