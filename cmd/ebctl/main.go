package main

import (
	"context"
	"os"

	"github.com/spf13/cobra"
)

var (
	version = "dev"
)

func main() {
	ctx := context.Background()

	cmd := &cobra.Command{
		Use:     "ebctl",
		Short:   "CLI for EdgeBit.io",
		Version: version,
		SilenceUsage: true,
	}

	cmd.AddCommand(uploadSBOMCommand())
	cmd.AddCommand(uploadSBOMCommandForCI())

	err := cmd.ExecuteContext(ctx)
	if err != nil {
		os.Exit(1)
	}
}
