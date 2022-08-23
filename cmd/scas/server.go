package main

import (
	"github.com/spf13/cobra"

	"scas"
)

func init() {
	cmd := &cobra.Command{
		Use:   "server",
		Short: "start Simple Certificate Authority Service",
		RunE:  func(cmd *cobra.Command, args []string) error { return scas.Run(cmd.Context()) },
	}

	rootCmd.AddCommand(cmd)
}
