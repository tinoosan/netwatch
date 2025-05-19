/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// scanCmd represents the scan command
var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Perform a one-time scan of a subnet",
	Long: `The scan command performs a single pass over a specified subnet and returns the list of active devices. 
It uses TCP handshakes to detect which hosts are online.

Output can be displayed as formatted text or JSON.

Example:
  netwatch scan --subnet 192.168.1.0/24 --output json`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("scan called")
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// scanCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// scanCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
