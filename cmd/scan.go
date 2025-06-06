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
var jobQueue int
var portWP *scan.PortWorkerPool
var defaultPorts int

func checkError(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v", err)
	}
}

// scanCmd represents the scan command
var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Perform a one-time scan of a subnet",
	Long: `The scan command performs a single pass over a specified subnet and returns the list of active devices. 
It uses ICMP ping to detect which hosts are online and then a TCP handshake to determine open ports.

Output can be displayed as formatted text or JSON.

Example:
  netwatch scan --subnet 192.168.1.0/24 --output json`,
	Run: func(cmd *cobra.Command, args []string) {

		subnet, err := cmd.Flags().GetString("subnet")
		checkError(err)
		ports, err := cmd.Flags().GetStringSlice("port")
		checkError(err)
		workers, err := cmd.Flags().GetInt("workers")
		checkError(err)

		start := time.Now()

		//fmt.Printf("flags set: subnet %s | output %s\n", subnet, output)
		hosts, err := scan.GenerateHosts(subnet)
		checkError(err)
		if len(hosts) == 0 {
			fmt.Printf("no hosts found in subnet %s\n", subnet)
			return
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

		var liveIPs []*scan.PingResult

		for result := range wp.Results {
			if result.Err != nil {
				checkError(result.Err)
			} else {
				liveIPs = append(liveIPs, result)
			}
		}

		if len(liveIPs) == 0 {
			fmt.Println("no hosts found")
		} else {
			fmt.Printf("found %v hosts that are up\n", len(liveIPs))
			fmt.Println("performing port scan...")

		if len(ports) > 0 && len(liveIPs) != 0 {
			jobQueue = len(liveIPs) * len(ports)
			portWP = scan.NewPortWorkerPool(workers, jobQueue)
		} else {
			defaultPorts = 6000
			jobQueue = len(liveIPs) * defaultPorts
			portWP = scan.NewPortWorkerPool(workers, jobQueue)
		}

		switch {
		case len(ports) > 0:
			fmt.Printf("creating job queue with %v jobs\n", jobQueue)
			for _, result := range liveIPs {
				for _, port := range ports {
					job := scan.PortJob{
						IP:      result.IP,
						Port:    port,
						Latency: result.Latency,
					}
					//fmt.Printf("adding job %+v to queue\n", job)
					portWP.AddJob(job)
				}
			}
			portWP.Start()
			portWP.Wait()
		default:
			fmt.Printf("using default port range 1-%v\n", defaultPorts)
			fmt.Printf("creating job queue with %v jobs\n", jobQueue)
			for _, result := range liveIPs {
				for i := 1; i <= defaultPorts; i++ {
					port := strconv.FormatInt(int64(i), 10)
					job := scan.PortJob{
						IP:      result.IP,
						Port:    port,
						Latency: result.Latency,
					}
					//fmt.Printf("adding job %+v to queue\n", job)
					portWP.AddJob(job)

				}
			}
			portWP.Start()
			portWP.Wait()
		}

		fmt.Printf("aggregating results...\n")

		var jobResults []scan.PortJob

		for result := range portWP.Results {
			jobResults = append(jobResults, result)
		}

		scanLog := make(map[string]Data)

		for _, job := range jobResults {
			data, exists := scanLog[job.IP]
			if !exists {
				data = Data{
					Ports:   []string{},
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

		filename := "scan.json"
		f, err1 := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		checkError(err1)

		_, err2 := f.WriteString(string(dataJSON))
		checkError(err2)

		f.Close()

		duration := time.Since(start)
		fmt.Printf("Scan complete! Duration: %s\n", duration)
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
	scanCmd.Flags().StringSliceP("port", "p", nil, "Port(s) to scan")
	scanCmd.Flags().IntP("workers", "w", 20, "Number of concurrent scans")
}
