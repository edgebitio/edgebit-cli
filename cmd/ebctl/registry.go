package main

import (
	"io"
	"os"

	"github.com/spf13/cobra"
)

func fetchSBOMCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "fetch-sbom",
		Short: "Fetch an SBOM",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			sbom, err := fetchSBOM(ctx, args[0])
			if err != nil {
				return err
			}

			// Nothing really productive to do with an error here
			_, _ = io.Copy(os.Stdout, sbom)

			return nil
		},
		Args: cobra.ExactArgs(1),
	}

	return cmd
}
