package main

import (
	"github.com/spf13/cobra"

	"scas/api/acme"
)

var acmeCmd *cobra.Command

func init() {
	acmeCmd = &cobra.Command{
		Use:   "acme",
		Short: "acme",
	}
	rootCmd.AddCommand(acmeCmd)
}

func init() {
	acmeCmd.AddCommand(&cobra.Command{
		Use:   "server",
		Short: "start acmd server",
		RunE:  func(cmd *cobra.Command, args []string) error { return acme.Run(cmd.Context()) },
	})
}
