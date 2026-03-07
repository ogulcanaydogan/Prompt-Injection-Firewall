package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/ogulcanaydogan/Prompt-Injection-Firewall/pkg/config"
	"github.com/ogulcanaydogan/Prompt-Injection-Firewall/pkg/webhook"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	var (
		configPath     string
		listen         string
		tlsCertFile    string
		tlsKeyFile     string
		pifHostPattern string
	)

	fs := flag.NewFlagSet("pif-webhook", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.StringVar(&configPath, "config", "", "path to config file")
	fs.StringVar(&listen, "listen", "", "webhook listen address")
	fs.StringVar(&tlsCertFile, "tls-cert-file", "", "TLS certificate file path")
	fs.StringVar(&tlsKeyFile, "tls-key-file", "", "TLS key file path")
	fs.StringVar(&pifHostPattern, "pif-host-pattern", "", "regex pattern that PIF base URLs must match")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "loading config: %v\n", err)
		return 2
	}

	opts := webhook.ServerOptions{
		Listen:         cfg.Webhook.Listen,
		TLSCertFile:    cfg.Webhook.TLSCertFile,
		TLSKeyFile:     cfg.Webhook.TLSKeyFile,
		PIFHostPattern: cfg.Webhook.PIFHostPattern,
	}

	if listen != "" {
		opts.Listen = listen
	}
	if tlsCertFile != "" {
		opts.TLSCertFile = tlsCertFile
	}
	if tlsKeyFile != "" {
		opts.TLSKeyFile = tlsKeyFile
	}
	if pifHostPattern != "" {
		opts.PIFHostPattern = pifHostPattern
	}

	if err := webhook.StartServer(opts); err != nil {
		fmt.Fprintf(os.Stderr, "starting webhook server: %v\n", err)
		return 1
	}
	return 0
}
