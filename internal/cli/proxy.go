package cli

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/ogulcanaydogan/Prompt-Injection-Firewall/pkg/detector"
	"github.com/ogulcanaydogan/Prompt-Injection-Firewall/pkg/proxy"
)

var (
	proxyTarget string
	proxyListen string
	proxyAction string
)

func newProxyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "proxy",
		Short: "Start the prompt injection firewall proxy",
		Long: `Start an HTTP reverse proxy that intercepts LLM API requests,
scans prompts for injection attacks, and blocks/flags/logs detected threats.

Usage with OpenAI:
  pif proxy --target https://api.openai.com --listen :8080
  export OPENAI_BASE_URL=http://localhost:8080/v1`,
		RunE: runProxy,
	}

	cmd.Flags().StringVar(&proxyTarget, "target", "https://api.openai.com", "upstream LLM API URL")
	cmd.Flags().StringVar(&proxyListen, "listen", ":8080", "proxy listen address")
	cmd.Flags().StringVar(&proxyAction, "action", "block", "action on detection: block, flag, log")

	return cmd
}

func runProxy(cmd *cobra.Command, args []string) error {
	d, err := buildDetector()
	if err != nil {
		return fmt.Errorf("building detector: %w", err)
	}

	ensemble := d.(*detector.EnsembleDetector)

	fmt.Fprintf(cmd.OutOrStdout(), "Starting PIF proxy\n")
	fmt.Fprintf(cmd.OutOrStdout(), "  Target:  %s\n", proxyTarget)
	fmt.Fprintf(cmd.OutOrStdout(), "  Listen:  %s\n", proxyListen)
	fmt.Fprintf(cmd.OutOrStdout(), "  Action:  %s\n", proxyAction)
	fmt.Fprintf(cmd.OutOrStdout(), "  Rules:   %d loaded\n", ensemble.RuleCount())

	return proxy.StartServer(proxyTarget, proxyListen, proxyAction, d)
}
