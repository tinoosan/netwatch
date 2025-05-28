/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/tinoosan/netwatch/internal/logger"
	"github.com/tinoosan/netwatch/internal/scan"
)

var pingLogger = logger.New("scan.log", "ping")

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

		subnet, _ := cmd.Flags().GetString("subnet")
	  output, _ := cmd.Flags().GetString("output")

		//fmt.Printf("flags set: subnet %s | output %s\n", subnet, output)

		hosts, err := scan.GenerateHosts(subnet)
		if err != nil {
			fmt.Println(err)
		}

		wp := scan.NewWorkerPool(20, len(hosts), pingLogger)

		for _, host := range hosts {
			job := &scan.Job{
				Target:     host,
				Attempts:   0,
				MaxRetries: 2,
			}
			wp.AddJob(job)
		}

		wp.Start()
		go wp.Process()
		wp.Wait()

		pingLogger.Close()

		type Data struct {
			BodyID int
			Seq int
			Duration string
			Attempts int
			ReceivedAt time.Time
		}


		resultsJson := make(map[string]Data)
		for result := range wp.Results {
			data := Data{
				BodyID: result.BodyID,
				Seq: result.Seq,
				Duration: result.Duration,
				Attempts: result.Attempts,
				ReceivedAt: result.ReceivedAt,
			}
			resultsJson[result.IP] = data

			if output == "text" {
			fmt.Printf("Host %v is up with latency of %s!\n", result.IP, result.Duration)
			}
		}
			res, err := json.MarshalIndent(resultsJson," ", "	")
			if err != nil {
				fmt.Println(err)
			}

			f, err := os.OpenFile("scan.json", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				fmt.Printf("json file could not be created: %v\n", err)
			}

			_, err = f.WriteString(string(res)+"\n")
			if err != nil {
				fmt.Println(err)
			}

		if output == "json" {
			fmt.Println(string(res))
		}

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
	scanCmd.Flags().StringP("subnet", "s", "192.168.0.0/24", "CIDR block of the subnet to scan")
	scanCmd.Flags().StringP("output", "o", "text", "Output format: text or json")
}
