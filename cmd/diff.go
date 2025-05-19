/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// diffCmd represents the diff command
var diffCmd = &cobra.Command{
	Use:   "diff",
	Short: "Compare the two most recent scans and show changes",
	Long: `Loads the two latest scan results and compares them to detect added or removed devices. 
Reports any hosts that are new since the last scan or no longer detected.

Example:
  netwatch devices diff --format text`,
	Run: func(cmd *cobra.Command, args []string) {
		output, _ := cmd.Flags().GetString("output")
		fmt.Printf("flags set: output %s\n", output)
	},
}

func init() {
	deviceCmd.AddCommand(diffCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// diffCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// diffCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	diffCmd.Flags().StringP("output", "o", "json", "Output format: text or json")
}
