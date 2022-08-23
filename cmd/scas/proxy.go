package main

import (
	"github.com/spf13/cobra"
)

func init() {
	cmd := &cobra.Command{
		Use:   "proxy",
		Short: "TLS/mTLS/ACME proxy services",
		RunE:  func(cmd *cobra.Command, args []string) error { panic("Not Implemented") },
	}

	rootCmd.AddCommand(cmd)
}
