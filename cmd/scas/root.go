package main

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var rootCmd = &cobra.Command{
	Use:   "scas",
	Short: "Simple Certificate Authority Service ",
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.Flags()
}

func initConfig() {
	viper.SetEnvPrefix("")
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		// log.Warn(err)
	}
}
