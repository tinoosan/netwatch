// Package scan contains the low level ICMP and TCP scanning primitives used by
// Netwatch. It provides worker pools for performing network operations in
// parallel and data structures for storing scan results.
package scan

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/tinoosan/netwatch/internal/logger"
)

// PortJob represents a single TCP port scan on a host.
type PortJob struct {
	Target *TargetHost
	Port   string
}

// PortScanResult captures the outcome of a TCP port scan.
type PortScanResult struct {
	Port string
	Open bool
	Err  error
}

// PortWorkerPool manages a pool of goroutines that perform TCP connection
// attempts based on enqueued PortJobs.
type PortWorkerPool struct {
	Workers  int
	JobQueue chan PortJob
	context  context.Context
	logger   *logger.Logger
	wg       *sync.WaitGroup
	mu       *sync.Mutex
}

// NewPortWorkerPool creates a pool that performs TCP port scans. The jobQueue
// argument determines how many pending PortJobs can be queued.
func NewPortWorkerPool(numOfWorkers int, jobQueue int, logger *logger.Logger, ctx context.Context) *PortWorkerPool {
	return &PortWorkerPool{
		Workers:  numOfWorkers,
		JobQueue: make(chan PortJob, jobQueue),
		context:  ctx,
		logger:   logger,
		wg:       &sync.WaitGroup{},
		mu:       &sync.Mutex{},
	}
}

// AddJob enqueues a PortJob for processing.
func (wp *PortWorkerPool) AddJob(job PortJob) {
	wp.JobQueue <- job
}

// Worker consumes PortJobs from the queue and attempts a TCP connection to the
// specified port.
func (wp *PortWorkerPool) Worker(id int) {
	defer wp.wg.Done()
	for job := range wp.JobQueue {

		select {
		case <-wp.context.Done():
			return
		default:
			wp.mu.Lock()
			hostIP := job.Target.IP.String()
			wp.mu.Unlock()

			port := job.Port
			addr := net.JoinHostPort(hostIP, port)
			//message := fmt.Sprintf("scanning port %v on host %v\n", job.Port, hostIP)
			//wp.logger.Log(message)
			conn, err := net.DialTimeout("tcp", addr, time.Duration(20*time.Millisecond))
			if err == nil {
				message2 := fmt.Sprint("Port", port, "open on host\n", hostIP)
				wp.logger.Log(message2)
				conn.Close()
				result := PortScanResult{
					Port: port,
					Open: true,
					Err:  nil,
				}

				wp.mu.Lock()
				job.Target.OpenPorts = append(job.Target.OpenPorts, result)
				wp.mu.Unlock()
			} else {
				//fmt.Printf("finished scanning port %v on host %v but got error %v\n", id, job.Port, job.Target.IP.String(), err)
				continue
			}

		}

	}
}

// Start launches the worker goroutines for the pool.
func (wp *PortWorkerPool) Start() {
	for i := 1; i <= wp.Workers; i++ {
		wp.wg.Add(1)
		go wp.Worker(i)
	}
}

// Wait blocks until all queued jobs are processed.
func (wp *PortWorkerPool) Wait() {
	close(wp.JobQueue)
	wp.wg.Wait()
}
