/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
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
		ports, err := cmd.Flags().GetStringSlice("port")
		if err != nil {
			fmt.Println("Error: ", err)
		}
		workers, _ := cmd.Flags().GetInt("workers")

		start := time.Now()

		//fmt.Printf("flags set: subnet %s | output %s\n", subnet, output)

		hosts, err := scan.GenerateHosts(subnet)
		if err != nil {
			fmt.Println(err)
		}


		wp := scan.NewWorkerPool(workers, len(hosts), pingLogger)

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
			Ports   []string `json:"openPorts"`
			Latency string   `json:"latency"`
		}

		filename := "scan.json"

		f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Println("Error: ", err)
		}

		defer f.Close()

		var liveIPs []*scan.PingResult

		for result := range wp.Results {
			liveIPs = append(liveIPs, result)
		}

		jobQueue := len(liveIPs) * len(ports)
		portWP := scan.NewPortWorkerPool(workers, jobQueue)
		switch {
		case len(ports) > 0:
			for _, result := range liveIPs {
				for _, port := range ports {
					job := &scan.PortJob{
						IP:      result.IP,
						Port:    port,
						Latency: result.Duration,
						Success: false,
					}
					fmt.Printf("adding job %+v to queue\n", job)
					portWP.AddJob(job)
				}
			}
			portWP.Start()
			portWP.Wait()
		default:
			jobQueue = len(liveIPs) * 65535
			for _, result := range liveIPs {
				for i := 1; i < 65535; i++ {
					port := strconv.FormatInt(int64(i), 10)
					job := &scan.PortJob{
						IP:      result.IP,
						Port:    port,
						Latency: result.Duration,
						Success: false,
					}
					fmt.Printf("adding job %+v to queue\n", job)
					portWP.AddJob(job)
				}
			}
			portWP.Start()
			portWP.Wait()
		}

		var jobResults []*scan.PortJob

		for result := range portWP.Results {
			fmt.Printf("retreiving result %+v\n", result)
			jobResults = append(jobResults, result)
		}

		scanLog := make(map[string]Data)

		for _, job := range jobResults {
			data, exists := scanLog[job.IP]
			if !exists {
				data = Data{
					Ports: []string{},
					Latency: job.Latency,
				}
			}
				data.Ports = append(data.Ports, job.Port)
			  scanLog[job.IP] = data
		}

		dataJSON, err := json.MarshalIndent(&scanLog, "", " ")
		if err != nil {
			fmt.Println("Error: ", err)
		}

		_, err = f.WriteString(string(dataJSON))
		if err != nil {
			fmt.Println("Error: ", err)
		}


		duration := time.Since(start)
		fmt.Printf("Scan complete! Duration: %s\n", duration)

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
	scanCmd.Flags().StringSliceP("port", "p", nil, "Port(s) to scan")
	scanCmd.Flags().IntP("workers", "w", 20, "Number of concurrent scans")
}
