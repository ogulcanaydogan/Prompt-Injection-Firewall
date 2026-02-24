package cli

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintf(cmd.OutOrStdout(), "pif version %s\n", Version)
			fmt.Fprintf(cmd.OutOrStdout(), "go: %s\n", runtime.Version())
			fmt.Fprintf(cmd.OutOrStdout(), "os/arch: %s/%s\n", runtime.GOOS, runtime.GOARCH)
		},
	}
}
