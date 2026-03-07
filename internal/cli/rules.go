package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ogulcanaydogan/Prompt-Injection-Firewall/pkg/rules"
)

func newRulesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rules",
		Short: "Manage detection rules",
	}

	cmd.AddCommand(newRulesListCmd())
	cmd.AddCommand(newRulesValidateCmd())

	return cmd
}

func newRulesListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list [directory]",
		Short: "List loaded detection rules",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := "rules"
			if len(args) > 0 {
				dir = args[0]
			}

			sets, err := rules.LoadDir(dir)
			if err != nil {
				return fmt.Errorf("loading rules: %w", err)
			}

			total := 0
			for _, rs := range sets {
				fmt.Fprintf(cmd.OutOrStdout(), "\n%s (v%s)\n", rs.Name, rs.Version)
				fmt.Fprintf(cmd.OutOrStdout(), "%s\n\n", strings.Repeat("-", len(rs.Name)+len(rs.Version)+4))

				fmt.Fprintf(cmd.OutOrStdout(), "  %-16s %-24s %-10s %-8s %s\n",
					"ID", "CATEGORY", "SEVERITY", "ENABLED", "NAME")

				for _, r := range rs.Rules {
					enabled := "yes"
					if !r.Enabled {
						enabled = "no"
					}
					sev := "unknown"
					switch r.Severity {
					case 0:
						sev = "info"
					case 1:
						sev = "low"
					case 2:
						sev = "medium"
					case 3:
						sev = "high"
					case 4:
						sev = "critical"
					}
					fmt.Fprintf(cmd.OutOrStdout(), "  %-16s %-24s %-10s %-8s %s\n",
						r.ID, r.Category, sev, enabled, r.Name)
				}
				total += len(rs.Rules)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "\nTotal: %d rules in %d rule sets\n", total, len(sets))
			return nil
		},
	}
}

func newRulesValidateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "validate [directory]",
		Short: "Validate rule YAML files",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := "rules"
			if len(args) > 0 {
				dir = args[0]
			}

			sets, err := rules.LoadDir(dir)
			if err != nil {
				return fmt.Errorf("validation failed: %w", err)
			}

			total := 0
			for _, rs := range sets {
				total += len(rs.Rules)
				fmt.Fprintf(cmd.OutOrStdout(), "OK  %s (%d rules)\n", rs.Name, len(rs.Rules))
			}

			fmt.Fprintf(cmd.OutOrStdout(), "\nAll %d rules in %d files validated successfully\n", total, len(sets))
			return nil
		},
	}
}
