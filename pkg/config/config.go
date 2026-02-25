package config

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

// Config holds all PIF configuration.
type Config struct {
	Detector  DetectorConfig  `mapstructure:"detector"`
	Rules     RulesConfig     `mapstructure:"rules"`
	Proxy     ProxyConfig     `mapstructure:"proxy"`
	Allowlist AllowlistConfig `mapstructure:"allowlist"`
	Logging   LoggingConfig   `mapstructure:"logging"`
}

type DetectorConfig struct {
	Threshold   float64       `mapstructure:"threshold"`
	MinSeverity string        `mapstructure:"min_severity"`
	TimeoutMs   int           `mapstructure:"timeout_ms"`
	Strategy    string        `mapstructure:"ensemble_strategy"`
	MLModelPath string        `mapstructure:"ml_model_path"`
	MLThreshold float64       `mapstructure:"ml_threshold"`
	Weights     WeightsConfig `mapstructure:"weights"`
}

// WeightsConfig defines ensemble weights for each detector type.
type WeightsConfig struct {
	Regex float64 `mapstructure:"regex"`
	ML    float64 `mapstructure:"ml"`
}

type RulesConfig struct {
	Paths       []string `mapstructure:"paths"`
	CustomPaths []string `mapstructure:"custom_paths"`
}

type ProxyConfig struct {
	Listen       string `mapstructure:"listen"`
	Target       string `mapstructure:"target"`
	Action       string `mapstructure:"action"`
	MaxBodySize  int64  `mapstructure:"max_body_size"`
	ReadTimeout  string `mapstructure:"read_timeout"`
	WriteTimeout string `mapstructure:"write_timeout"`
}

type AllowlistConfig struct {
	Patterns []string `mapstructure:"patterns"`
	Hashes   []string `mapstructure:"hashes"`
}

type LoggingConfig struct {
	Level      string `mapstructure:"level"`
	Format     string `mapstructure:"format"`
	Output     string `mapstructure:"output"`
	LogPrompts bool   `mapstructure:"log_prompts"`
}

// Default returns a Config with sensible defaults.
func Default() *Config {
	return &Config{
		Detector: DetectorConfig{
			Threshold:   0.5,
			MinSeverity: "low",
			TimeoutMs:   100,
			Strategy:    "weighted",
			MLModelPath: "",
			MLThreshold: 0.85,
			Weights: WeightsConfig{
				Regex: 0.6,
				ML:    0.4,
			},
		},
		Rules: RulesConfig{
			Paths: []string{
				"rules/owasp-llm-top10.yaml",
				"rules/jailbreak-patterns.yaml",
				"rules/data-exfil.yaml",
			},
		},
		Proxy: ProxyConfig{
			Listen:       ":8080",
			Target:       "https://api.openai.com",
			Action:       "block",
			MaxBodySize:  1048576, // 1MB
			ReadTimeout:  "10s",
			WriteTimeout: "30s",
		},
		Logging: LoggingConfig{
			Level:      "info",
			Format:     "json",
			Output:     "stderr",
			LogPrompts: false,
		},
	}
}

// Load reads configuration from the given file path, environment variables,
// and applies defaults.
func Load(path string) (*Config, error) {
	v := viper.New()

	// Set defaults
	defaults := Default()
	v.SetDefault("detector.threshold", defaults.Detector.Threshold)
	v.SetDefault("detector.min_severity", defaults.Detector.MinSeverity)
	v.SetDefault("detector.timeout_ms", defaults.Detector.TimeoutMs)
	v.SetDefault("detector.ensemble_strategy", defaults.Detector.Strategy)
	v.SetDefault("detector.ml_model_path", defaults.Detector.MLModelPath)
	v.SetDefault("detector.ml_threshold", defaults.Detector.MLThreshold)
	v.SetDefault("detector.weights.regex", defaults.Detector.Weights.Regex)
	v.SetDefault("detector.weights.ml", defaults.Detector.Weights.ML)
	v.SetDefault("rules.paths", defaults.Rules.Paths)
	v.SetDefault("proxy.listen", defaults.Proxy.Listen)
	v.SetDefault("proxy.target", defaults.Proxy.Target)
	v.SetDefault("proxy.action", defaults.Proxy.Action)
	v.SetDefault("proxy.max_body_size", defaults.Proxy.MaxBodySize)
	v.SetDefault("proxy.read_timeout", defaults.Proxy.ReadTimeout)
	v.SetDefault("proxy.write_timeout", defaults.Proxy.WriteTimeout)
	v.SetDefault("logging.level", defaults.Logging.Level)
	v.SetDefault("logging.format", defaults.Logging.Format)
	v.SetDefault("logging.output", defaults.Logging.Output)
	v.SetDefault("logging.log_prompts", defaults.Logging.LogPrompts)

	// Environment variables: PIF_DETECTOR_THRESHOLD, PIF_PROXY_LISTEN, etc.
	v.SetEnvPrefix("PIF")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	// Read config file if provided
	if path != "" {
		v.SetConfigFile(path)
		if err := v.ReadInConfig(); err != nil {
			return nil, fmt.Errorf("reading config file: %w", err)
		}
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	return &cfg, nil
}
