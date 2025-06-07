package scan

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/tinoosan/netwatch/internal/logger"
)

type PortJob struct {
	Target *TargetHost
	Port   string
}

type PortScanResult struct {
	Port string
	Open bool
	Err  error
}

type PortWorkerPool struct {
	Workers  int
	JobQueue chan PortJob
	logger   *logger.Logger
	wg       *sync.WaitGroup
	mu       *sync.Mutex
}

func NewPortWorkerPool(numOfWorkers int, jobQueue int, logger *logger.Logger) *PortWorkerPool {
	return &PortWorkerPool{
		Workers:  numOfWorkers,
		JobQueue: make(chan PortJob, jobQueue),
		logger: logger,
		wg:       &sync.WaitGroup{},
		mu:       &sync.Mutex{},
	}
}

func (wp *PortWorkerPool) AddJob(job PortJob) {
	wp.JobQueue <- job
}

func (wp *PortWorkerPool) Worker(id int) {
	defer wp.wg.Done()
	for job := range wp.JobQueue {

		wp.mu.Lock()
		hostIP := job.Target.IP.String()
		wp.mu.Unlock()

		port := job.Port
		addr := net.JoinHostPort(hostIP, port)
	  message := fmt.Sprintf("scanning port %v on host %v\n", job.Port, hostIP)
		wp.logger.Log(message)
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

func (wp *PortWorkerPool) Start() {
	for i := 1; i <= wp.Workers; i++ {
		wp.wg.Add(1)
		go wp.Worker(i)
	}
}

func (wp *PortWorkerPool) Wait() {
	close(wp.JobQueue)
	wp.wg.Wait()
}
