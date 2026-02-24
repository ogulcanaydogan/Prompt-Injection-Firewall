package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	cfgFile string
	Version = "dev"
)

func NewRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "pif",
		Short: "Prompt Injection Firewall — detect and prevent LLM prompt injection attacks",
		Long: `PIF (Prompt Injection Firewall) is a real-time prompt injection detection
and prevention tool for LLM applications. It scans prompts for injection
attempts, jailbreaks, data exfiltration, and other attacks mapped to the
OWASP LLM Top 10.`,
		SilenceUsage: true,
	}

	root.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file (default: ./config.yaml)")

	root.AddCommand(newScanCmd())
	root.AddCommand(newRulesCmd())
	root.AddCommand(newProxyCmd())
	root.AddCommand(newVersionCmd())

	return root
}

func Execute() {
	if err := NewRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}
