/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// logsCmd represents the logs command
var logsCmd = &cobra.Command{
	Use:   "logs",
	Short: "View and filter Netwatch log output",
	Long: `Reads the Netwatch log file and optionally filters by time or device. You can use this to 
inspect historical scan results, device changes, or internal system events.

Example:
  netwatch logs --since 1h --device 192.168.1.42 --limit 50`,
	Run: func(cmd *cobra.Command, args []string) {
		since, _ := cmd.Flags().GetString("since")
		device, _ := cmd.Flags().GetString("device")
		limit, _ := cmd.Flags().GetInt("limit")

		fmt.Printf("flags set: since %s | device %s | limit %d\n", since, device, limit)
	},
}

func init() {
	rootCmd.AddCommand(logsCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// logsCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// logsCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	logsCmd.Flags().StringP("since","s", "", "Show logs since a given time (e.g. '1h', '2025-05-18T10:00)'")
	logsCmd.Flags().StringP("device", "d", "", "Filter logs by IP or MAC address")
	logsCmd.Flags().IntP("limit", "l", 100, "Limit number of log lines shown")
}
