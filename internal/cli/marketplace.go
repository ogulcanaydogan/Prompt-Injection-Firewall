package cli

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ogulcanaydogan/Prompt-Injection-Firewall/pkg/config"
	"github.com/ogulcanaydogan/Prompt-Injection-Firewall/pkg/marketplace"
)

func newMarketplaceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "marketplace",
		Short: "Manage community rule marketplace packages",
	}

	cmd.AddCommand(newMarketplaceListCmd())
	cmd.AddCommand(newMarketplaceInstallCmd())
	cmd.AddCommand(newMarketplaceUpdateCmd())

	return cmd
}

func newMarketplaceListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List available community packages from marketplace index",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadCLIConfig()
			if err != nil {
				return err
			}
			if !cfg.Marketplace.Enabled {
				return fmt.Errorf("marketplace is disabled (set marketplace.enabled=true)")
			}
			items, err := marketplace.List(context.Background(), marketplaceFromConfig(cfg))
			if err != nil {
				return err
			}

			fmt.Fprintf(cmd.OutOrStdout(), "%-24s %-10s %-20s %s\n", "ID", "VERSION", "MAINTAINER", "CATEGORIES")
			for _, item := range items {
				fmt.Fprintf(cmd.OutOrStdout(), "%-24s %-10s %-20s %s\n", item.ID, item.Version, item.Maintainer, strings.Join(item.Categories, ","))
			}
			fmt.Fprintf(cmd.OutOrStdout(), "\nTotal: %d packages\n", len(items))
			return nil
		},
	}
}

func newMarketplaceInstallCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "install <id>@<version>",
		Short: "Install a community package into marketplace install_dir",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadCLIConfig()
			if err != nil {
				return err
			}
			if !cfg.Marketplace.Enabled {
				return fmt.Errorf("marketplace is disabled (set marketplace.enabled=true)")
			}
			installed, err := marketplace.Install(context.Background(), marketplaceFromConfig(cfg), args[0])
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Installed %s@%s -> %s\n", installed.Entry.ID, installed.Entry.Version, installed.FilePath)
			return nil
		},
	}
}

func newMarketplaceUpdateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "update",
		Short: "Update installed community packages to latest versions",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadCLIConfig()
			if err != nil {
				return err
			}
			if !cfg.Marketplace.Enabled {
				return fmt.Errorf("marketplace is disabled (set marketplace.enabled=true)")
			}
			result, err := marketplace.Update(context.Background(), marketplaceFromConfig(cfg))
			if err != nil {
				return err
			}
			for _, updated := range result.Updated {
				fmt.Fprintf(cmd.OutOrStdout(), "updated: %s@%s -> %s\n", updated.Entry.ID, updated.Entry.Version, updated.FilePath)
			}
			for _, skipped := range result.Skipped {
				fmt.Fprintf(cmd.OutOrStdout(), "skipped: %s\n", skipped)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "summary: updated=%d skipped=%d\n", len(result.Updated), len(result.Skipped))
			return nil
		},
	}
}

func loadCLIConfig() (*config.Config, error) {
	path := cfgFile
	if path == "" {
		if _, err := os.Stat("config.yaml"); err == nil {
			path = "config.yaml"
		}
	}
	cfg, err := config.Load(path)
	if err != nil {
		return nil, fmt.Errorf("loading config: %w", err)
	}
	return cfg, nil
}

func marketplaceFromConfig(cfg *config.Config) marketplace.Config {
	refresh := cfg.Marketplace.RefreshIntervalMinutes
	if refresh <= 0 {
		refresh = 60
	}
	return marketplace.Config{
		Enabled:                cfg.Marketplace.Enabled,
		IndexURL:               cfg.Marketplace.IndexURL,
		CacheDir:               cfg.Marketplace.CacheDir,
		InstallDir:             cfg.Marketplace.InstallDir,
		RefreshIntervalMinutes: refresh,
		RequireChecksum:        cfg.Marketplace.RequireChecksum,
	}
}
