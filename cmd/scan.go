/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/

// Scan flow:
// 1. Generate IPs from CIDR
// 2. Create PingJobs for each host
// 3. Start PingWorkerPool, wait for completion
// 4. Collect live hosts
// 5. For each live host, create PortJobs for each port
// 6. Start PortWorkerPool, wait for completion
// 7. Print or save results

package cmd

import (
	//"encoding/json"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"time"

	"github.com/spf13/cobra"
	"github.com/tinoosan/netwatch/internal/logger"
	"github.com/tinoosan/netwatch/internal/scan"
)

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

		var logger = logger.New("scan.log", "scan")
		defer logger.Close()
		var jobQueue int
		var portWP *scan.PortWorkerPool
		var defaultPorts int
		var liveTargets []*scan.TargetHost

		subnet, err := cmd.Flags().GetString("subnet")
		checkError(err)
		ports, err := cmd.Flags().GetStringSlice("port")
		checkError(err)
		workers, err := cmd.Flags().GetInt("workers")
		checkError(err)

		systemIPNet, hwAddr, err := scan.GetSystemInfo()
		if err != nil {
			logger.Log(err.Error())
		}

		if subnet == "" {
			subnet = systemIPNet.String()
		}

		fmt.Printf("Subnet: %v\n", subnet)
		fmt.Printf("System MAC: %v\n", hwAddr.String())

		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
		defer cancel()
		
		start := time.Now()

		type Data struct {
			Timestamp string
			Result map[string]*scan.TargetHost
		}
		data := &Data{Result: make(map[string]*scan.TargetHost)}

		//Step 1: Generate hosts from subnet CIDR
		fmt.Println("generating hosts for subnet", subnet)
		hosts, err := scan.GenerateHosts(subnet)
		checkError(err)
		if len(hosts) == 0 {
			fmt.Printf("no hosts found in subnet %s\n", subnet)
			return
		} else {
			fmt.Printf("generated %d possible hosts\n", len(hosts))
		}

		fmt.Println("initializing scan...")
		pingWorkerPool := scan.NewPingWorkerPool(workers, len(hosts), logger, ctx)

		//fmt.Printf("hosts: %v\n", hosts)

		//Step 2: Use hosts to create jobs for workers and add them to worker pool for ping job.
		//This will allow each worker to mutate the host with the result of the job reducing the need for
		// a result channel
		for i, host := range hosts {
			job := &scan.PingJob{
				ID:         scan.GenerateEchoID(host.IP, i),
				Target:     host,
				ResultChan: make(chan *scan.PingResult, 1),
				Attempts:   0,
				MaxRetries: 2,
			}
			pingWorkerPool.AddJob(job)
		}

		//Step 3: Start the job
		pingWorkerPool.Start()
		go pingWorkerPool.Process()
		pingWorkerPool.Wait()

		//Step 4: Collect the live hosts.
		for _, host := range hosts {
			if host.ICMPErr != nil {
				logger.Log(host.ICMPErr.Error())
			}

			if host.Up {
				liveTargets = append(liveTargets, host)
			}
		}

		if len(liveTargets) == 0 {
			fmt.Println("no hosts found")
		} else {
			fmt.Printf("found %v hosts that are up\n", len(liveTargets))
			//Step 5: Start the port scan by creating the jobs and then starting the worker pool.
			fmt.Println("performing port scan...")

			if len(ports) > 0 && len(liveTargets) != 0 {
				jobQueue = len(liveTargets) * len(ports)
				portWP = scan.NewPortWorkerPool(workers, jobQueue, logger, ctx)
			} else {
				defaultPorts = 6000
				jobQueue = len(liveTargets) * defaultPorts
				portWP = scan.NewPortWorkerPool(workers, jobQueue, logger, ctx)
			}

			switch {
			case len(ports) > 0:
				fmt.Printf("creating job queue with %v jobs\n", jobQueue)
				for _, target := range liveTargets {
					for _, port := range ports {
						job := scan.PortJob{
							Target: target,
							Port:   port,
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
				for _, target := range liveTargets {
					for i := 1; i <= defaultPorts; i++ {
						port := strconv.FormatInt(int64(i), 10)
						job := scan.PortJob{
							Target: target,
							Port:   port,
						}
						//fmt.Printf("adding job %+v to queue\n", job)
						portWP.AddJob(job)

					}
				}
				portWP.Start()
				portWP.Wait()
			}

			for _, target := range liveTargets {
				data.Result[target.IP.String()] = target
			}

			duration := time.Since(start)
			fmt.Printf("Scan complete! Duration: %s\n", duration)
		}

		data.Timestamp = time.Now().Format("2006-01-02T15:04:05")

		f, err := os.OpenFile("scan.json", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Println(err)
		}

		dataJSON, err := json.MarshalIndent(data, " ", "  ")
		if err != nil {
			fmt.Println(err)
		}

		_, err = f.Write(dataJSON)
		if err != nil {
			fmt.Println(err)
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
	scanCmd.Flags().StringP("subnet", "s", "", "CIDR block of the subnet to scan")
	scanCmd.Flags().StringSliceP("port", "p", nil, "Port(s) to scan")
	scanCmd.Flags().IntP("workers", "w", 20, "Number of concurrent scans")
}
