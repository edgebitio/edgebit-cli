package main

import (
	"context"
	"fmt"
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
	}

	cmd.AddCommand(uploadSBOMCommand())
	cmd.AddCommand(uploadSBOMCommandForCI())
	cmd.AddCommand(fetchSBOMCommand())

	err := cmd.ExecuteContext(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
