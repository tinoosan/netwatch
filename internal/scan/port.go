package scan

import (
	"fmt"
	"net"
	"sync"
	"time"
)

type PortJob struct {
	Target *TargetHost
	Port    string
}

type PortScanResult struct {
	Port string
	Open bool
	Err error
}

type PortWorkerPool struct {
	Workers  int
	JobQueue chan PortJob
	Results  chan PortJob
	wg       *sync.WaitGroup
}

func NewPortWorkerPool(numOfWorkers int, jobQueue int) *PortWorkerPool {
	return &PortWorkerPool{
		Workers:  numOfWorkers,
		JobQueue: make(chan PortJob, jobQueue),
		wg:       &sync.WaitGroup{},
	}
}

func (wp *PortWorkerPool) AddJob(job PortJob) {
	wp.JobQueue <- job
}

func (wp *PortWorkerPool) Worker(id int) {
	defer wp.wg.Done()
	for job := range wp.JobQueue {
		addr := net.JoinHostPort(job.Target.IP.String(), job.Port)
		//fmt.Printf("worker %v scanning port %v on host %v\n", id, job.Port, job.IP)
		conn, err := net.DialTimeout("tcp", addr, time.Duration(20*time.Millisecond))
		if err == nil {
			fmt.Println("Port", job.Port, "open on host", job.Target.IP.String())
			//fmt.Printf("worker %v finished scanning port %v on host %v\n", id, job.Port, job.IP)
			conn.Close()
			result := PortScanResult{
				Port: job.Port,
				Open: true,
				Err: nil,
			}
			job.Target.OpenPorts = append(job.Target.OpenPorts, result)
		} else {
			//fmt.Printf("worker %v finished scanning port %v on host %v but got error %v\n", id, job.Port, job.Target.IP.String(), err)
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
