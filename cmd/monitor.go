/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// monitorCmd represents the monitor command
var monitorCmd = &cobra.Command{
	Use:   "monitor",
	Short: "Continuously scan a subnet and track device changes",
	Long: `The monitor command runs a background process that continuously scans a local subnet at a fixed interval. 
It identifies connected devices by attempting TCP connections to known ports, detects new or missing devices 
by comparing the current scan to the previous one, and logs all changes to a log file.

You can optionally expose a local HTTP server to view status and history via endpoints like /status and /history.

Example:
  netwatch monitor --subnet 192.168.1.0/24 --interval 300 --port 9000 --logfile ./netwatch.log`,
	Run: func(cmd *cobra.Command, args []string) {
		subnet, _ := cmd.Flags().GetString("subnet")
		interval, _ := cmd.Flags().GetInt("interval")
		port, _ := cmd.Flags().GetInt("port")
		logfile, _ := cmd.Flags().GetString("logfile")
		env, _ := cmd.Flags().GetString("env")
		fmt.Printf("flags set: subnet %s | interval %d | port %d | logfile %s | env %s\n", subnet, interval, port, logfile, env)
	},
}


func init() {
	rootCmd.AddCommand(monitorCmd)


	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// monitorCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	//monitorCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	monitorCmd.Flags().StringP("subnet", "s", "192.168.1.0/24", "CIDR block of the subnet to scan")
	monitorCmd.Flags().IntP("interval", "i", 300, "Scan frequency in seconds")
	monitorCmd.Flags().IntP("port", "p", 9000, "Port to run the optional HTTP status server (0 disables)")
	monitorCmd.Flags().StringP("logfile", "l", "./netwatch.log", "Path to write logs to")
	monitorCmd.Flags().StringP("env", "e", "dev", "Environment mode: dev or prod")

}
