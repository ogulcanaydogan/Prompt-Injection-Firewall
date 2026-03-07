package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/ogulcanaydogan/Prompt-Injection-Firewall/pkg/config"
	"github.com/ogulcanaydogan/Prompt-Injection-Firewall/pkg/detector"
	"github.com/ogulcanaydogan/Prompt-Injection-Firewall/pkg/proxy"
	"github.com/spf13/cobra"
)

var (
	proxyTarget string
	proxyListen string
	proxyAction string
	proxyModel  string
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
	cmd.Flags().StringVarP(&proxyModel, "model", "m", "", "path to ONNX model directory or HuggingFace model ID")

	return cmd
}

func runProxy(cmd *cobra.Command, args []string) error {
	configPath := cfgFile
	if configPath == "" {
		if _, err := os.Stat("config.yaml"); err == nil {
			configPath = "config.yaml"
		}
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	target := cfg.Proxy.Target
	listen := cfg.Proxy.Listen
	action := cfg.Proxy.Action
	if cmd.Flags().Lookup("target").Changed {
		target = proxyTarget
	}
	if cmd.Flags().Lookup("listen").Changed {
		listen = proxyListen
	}
	if cmd.Flags().Lookup("action").Changed {
		action = proxyAction
	}

	// If proxy has --model, propagate to scan's model var for buildDetector().
	// Otherwise, use config-provided model path.
	if proxyModel != "" {
		scanModel = proxyModel
	} else {
		scanModel = cfg.Detector.MLModelPath
	}

	// If proxy has --model, propagate to scan's model var for buildDetector()
	readTimeout, err := time.ParseDuration(cfg.Proxy.ReadTimeout)
	if err != nil {
		return fmt.Errorf("parsing proxy.read_timeout: %w", err)
	}

	writeTimeout, err := time.ParseDuration(cfg.Proxy.WriteTimeout)
	if err != nil {
		return fmt.Errorf("parsing proxy.write_timeout: %w", err)
	}

	d, err := buildDetector()
	if err != nil {
		return fmt.Errorf("building detector: %w", err)
	}

	ensemble := d.(*detector.EnsembleDetector)

	mlStatus := "disabled"
	if ensemble.HasMLDetector() {
		mlStatus = "enabled"
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Starting PIF proxy\n")
	fmt.Fprintf(cmd.OutOrStdout(), "  Target:     %s\n", target)
	fmt.Fprintf(cmd.OutOrStdout(), "  Listen:     %s\n", listen)
	fmt.Fprintf(cmd.OutOrStdout(), "  Action:     %s\n", action)
	fmt.Fprintf(cmd.OutOrStdout(), "  Rules:      %d loaded\n", ensemble.RuleCount())
	fmt.Fprintf(cmd.OutOrStdout(), "  ML:         %s\n", mlStatus)
	fmt.Fprintf(cmd.OutOrStdout(), "  Detectors:  %d\n", ensemble.DetectorCount())
	fmt.Fprintf(cmd.OutOrStdout(), "  Threshold:  %.2f\n", cfg.Detector.Threshold)

	return proxy.StartServer(proxy.ServerOptions{
		TargetURL:    target,
		Listen:       listen,
		Action:       action,
		Threshold:    cfg.Detector.Threshold,
		MaxBodySize:  cfg.Proxy.MaxBodySize,
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
		RateLimit: proxy.RateLimitOptions{
			Enabled:           cfg.Proxy.RateLimit.Enabled,
			RequestsPerMinute: cfg.Proxy.RateLimit.RequestsPerMinute,
			Burst:             cfg.Proxy.RateLimit.Burst,
			KeyHeader:         cfg.Proxy.RateLimit.KeyHeader,
		},
		AdaptiveThreshold: proxy.AdaptiveThresholdOptions{
			Enabled:      cfg.Detector.AdaptiveThreshold.Enabled,
			MinThreshold: cfg.Detector.AdaptiveThreshold.MinThreshold,
			EWMAAlpha:    cfg.Detector.AdaptiveThreshold.EWMAAlpha,
		},
	}, d)
}
