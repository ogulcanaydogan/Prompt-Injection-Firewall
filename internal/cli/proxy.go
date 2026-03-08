package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/ogulcanaydogan/Prompt-Injection-Firewall/pkg/config"
	"github.com/ogulcanaydogan/Prompt-Injection-Firewall/pkg/detector"
	"github.com/ogulcanaydogan/Prompt-Injection-Firewall/pkg/proxy"
	"github.com/ogulcanaydogan/Prompt-Injection-Firewall/pkg/rules"
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

	modelPath := resolveProxyModelPath(cfg)

	readTimeout, err := time.ParseDuration(cfg.Proxy.ReadTimeout)
	if err != nil {
		return fmt.Errorf("parsing proxy.read_timeout: %w", err)
	}

	writeTimeout, err := time.ParseDuration(cfg.Proxy.WriteTimeout)
	if err != nil {
		return fmt.Errorf("parsing proxy.write_timeout: %w", err)
	}
	alertingOptions, err := parseAlertingOptions(cfg)
	if err != nil {
		return err
	}

	detectorFactory := buildProxyDetectorFactory(cfg, modelPath)
	ruleManager, err := proxy.NewRuntimeRuleManager(proxy.RuntimeRuleManagerOptions{
		RulePaths:       cfg.Rules.Paths,
		CustomPaths:     cfg.Rules.CustomPaths,
		DetectorFactory: detectorFactory,
	})
	if err != nil {
		return fmt.Errorf("initializing runtime rule manager: %w", err)
	}

	currentDetector := ruleManager.CurrentDetector()
	if currentDetector == nil {
		return fmt.Errorf("runtime detector not initialized")
	}
	ensemble, ok := currentDetector.(*detector.EnsembleDetector)
	if !ok {
		return fmt.Errorf("unexpected detector type: %T", currentDetector)
	}

	ruleSnapshot := ruleManager.Snapshot()
	mlStatus := "disabled"
	if ensemble.HasMLDetector() {
		mlStatus = "enabled"
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Starting PIF proxy\n")
	fmt.Fprintf(cmd.OutOrStdout(), "  Target:     %s\n", target)
	fmt.Fprintf(cmd.OutOrStdout(), "  Listen:     %s\n", listen)
	fmt.Fprintf(cmd.OutOrStdout(), "  Action:     %s\n", action)
	fmt.Fprintf(cmd.OutOrStdout(), "  Rules:      %d loaded\n", ruleSnapshot.TotalRules)
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
		Dashboard: proxy.DashboardOptions{
			Enabled:               cfg.Dashboard.Enabled,
			Path:                  cfg.Dashboard.Path,
			APIPrefix:             cfg.Dashboard.APIPrefix,
			RefreshSeconds:        cfg.Dashboard.RefreshSeconds,
			RuleManagementEnabled: cfg.Dashboard.RuleManagement.Enabled,
			Auth: proxy.DashboardAuthOptions{
				Enabled:  cfg.Dashboard.Auth.Enabled,
				Username: cfg.Dashboard.Auth.Username,
				Password: cfg.Dashboard.Auth.Password,
			},
		},
		RuleInventory: ruleSnapshot.RuleSets,
		RuleManager:   ruleManager,
		Alerting:      alertingOptions,
	}, ruleManager.Detector())
}

func resolveProxyModelPath(cfg *config.Config) string {
	if proxyModel != "" {
		scanModel = proxyModel
		return proxyModel
	}
	if cfg.Detector.MLModelPath != "" {
		scanModel = cfg.Detector.MLModelPath
		return cfg.Detector.MLModelPath
	}
	return ""
}

func buildProxyDetectorFactory(cfg *config.Config, modelPath string) proxy.DetectorFactory {
	strategy := detector.ParseStrategy(cfg.Detector.Strategy)
	timeout := time.Duration(cfg.Detector.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 100 * time.Millisecond
	}
	regexWeight := cfg.Detector.Weights.Regex
	if regexWeight <= 0 {
		regexWeight = 1.0
	}
	mlWeight := cfg.Detector.Weights.ML
	if mlWeight <= 0 {
		mlWeight = 0.4
	}
	mlThreshold := cfg.Detector.MLThreshold
	if mlThreshold <= 0 {
		mlThreshold = 0.85
	}

	return func(ruleSets []rules.RuleSet) (detector.Detector, error) {
		regexDetector, err := detector.NewRegexDetector(ruleSets...)
		if err != nil {
			return nil, err
		}

		ensemble := detector.NewEnsemble(strategy, timeout)
		ensemble.Register(regexDetector, regexWeight)

		if modelPath != "" {
			mlDetector, mlErr := detector.NewMLDetector(detector.MLConfig{
				ModelPath: modelPath,
				Threshold: mlThreshold,
			})
			if mlErr == nil {
				ensemble.Register(mlDetector, mlWeight)
			}
		}

		return ensemble, nil
	}
}

func parseAlertingOptions(cfg *config.Config) (proxy.AlertingOptions, error) {
	webhookTimeout, err := time.ParseDuration(cfg.Alerting.Webhook.Timeout)
	if err != nil {
		return proxy.AlertingOptions{}, fmt.Errorf("parsing alerting.webhook.timeout: %w", err)
	}
	slackTimeout, err := time.ParseDuration(cfg.Alerting.Slack.Timeout)
	if err != nil {
		return proxy.AlertingOptions{}, fmt.Errorf("parsing alerting.slack.timeout: %w", err)
	}
	throttleWindow := time.Duration(cfg.Alerting.Throttle.WindowSeconds) * time.Second
	if throttleWindow <= 0 {
		throttleWindow = 60 * time.Second
	}

	return proxy.AlertingOptions{
		Enabled:   cfg.Alerting.Enabled,
		QueueSize: cfg.Alerting.QueueSize,
		Events: proxy.AlertingEventOptions{
			Block:     cfg.Alerting.Events.Block,
			RateLimit: cfg.Alerting.Events.RateLimit,
			ScanError: cfg.Alerting.Events.ScanError,
		},
		ThrottleWindow: throttleWindow,
		Webhook: proxy.AlertingSinkOptions{
			Enabled:         cfg.Alerting.Webhook.Enabled,
			URL:             cfg.Alerting.Webhook.URL,
			Timeout:         webhookTimeout,
			MaxRetries:      cfg.Alerting.Webhook.MaxRetries,
			BackoffInitial:  time.Duration(cfg.Alerting.Webhook.BackoffInitialMs) * time.Millisecond,
			AuthBearerToken: cfg.Alerting.Webhook.AuthBearerToken,
		},
		Slack: proxy.AlertingSinkOptions{
			Enabled:        cfg.Alerting.Slack.Enabled,
			URL:            cfg.Alerting.Slack.IncomingWebhookURL,
			Timeout:        slackTimeout,
			MaxRetries:     cfg.Alerting.Slack.MaxRetries,
			BackoffInitial: time.Duration(cfg.Alerting.Slack.BackoffInitialMs) * time.Millisecond,
		},
	}, nil
}
