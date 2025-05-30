package scan

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/tinoosan/netwatch/internal/logger"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

type PingResult struct {
	IP         string    `json:"ipAddress"`
	BodyID     int       `json:"bodyID"`
	Seq        int       `json:"sequenceNumber"`
	Duration   string    `json:"duration"`
	Attempts   int       `json:"attempts"`
	ReceivedAt time.Time `json:"receivedAt"`
}

type Job struct {
	ID         int
	Target     net.IP
	Result     chan *PingResult
	SentAt     time.Time
	Attempts   int
	MaxRetries int
}

type WorkerPool struct {
	Workers     int
	JobQueue    chan *Job
	Results     chan *PingResult
	PendingJobs map[int]*Job
	wg          *sync.WaitGroup
	logger      *logger.Logger
	conn        *icmp.PacketConn
	mu          *sync.Mutex
}

const (
	ListenAddress = "0.0.0.0"
	IPv4Protocol  = 1
)

var (
	ErrResolveIPAddr = errors.New("failed to resolve to target address %v: %w\n")
	ErrSocketConn    = errors.New("failed to create raw socket to listen for ICMP packets: %w\n")
	ErrMarshalMsg    = errors.New("failed to marshal icmp message: %w\n")
	ErrWrite         = errors.New("failed to send ICMP message: %w\n")
	ErrRead          = errors.New("failed to read ICMP response message: %w\n")
	ErrDeadline      = errors.New("failed to set read deadline: %w\n")
	ErrParse         = errors.New("failed to parse ICMP message: %w\n")
	ErrParseSubnet   = errors.New("failed to parse subnet %v: %w\n")
	ErrMaskDecode    = errors.New("failed to decode mask %v: %w\n")
)

func NewWorkerPool(numOfWorkers int, jobQueue int, pingLogger *logger.Logger) *WorkerPool {
	wg := &sync.WaitGroup{}
	conn, err := icmp.ListenPacket("ip4:icmp", ListenAddress)
	if err != nil {
		fmt.Printf(ErrSocketConn.Error(), err)
	}
	return &WorkerPool{
		Workers:     numOfWorkers,
		JobQueue:    make(chan *Job, jobQueue),
		Results:     make(chan *PingResult, jobQueue),
		wg:          wg,
		logger:      pingLogger,
		conn:        conn,
		PendingJobs: make(map[int]*Job),
		mu:          &sync.Mutex{},
	}
}

func (wp *WorkerPool) Worker(id int) {
	defer wp.wg.Done()
	for job := range wp.JobQueue {
		resultCh := make(chan *PingResult, 1)
		echoID := generateEchoID(job.Target, id)

		job.ID = echoID
		job.Result = resultCh
		job.SentAt = time.Now()

		wp.mu.Lock()
		wp.PendingJobs[echoID] = job
		wp.mu.Unlock()

		replyReceived := false

		attempts := 1
		seq := 0
		for attempts <= job.MaxRetries && !replyReceived {
			job.Attempts = job.Attempts + 1
			//fmt.Printf("Attempt: %d Worker %d pinging IP %v with echoID %v\n", job.Attempts, id, job.Target, echoID)
			err := wp.SendPing(job.Target, echoID, seq)
			if err != nil {
				fmt.Println(err)
			}
			attempts++
			seq++

			select {
			case result := <-resultCh:
				wp.Results <- result
				replyReceived = true
				time.Sleep(1 * time.Second)
			case <-time.After(2 * time.Second):
			}
		} 
		if replyReceived {
			wp.cleanup(resultCh, echoID)
		}
	}
}


func (wp *WorkerPool) AddJob(job *Job) {
	wp.JobQueue <- job
}

func (wp *WorkerPool) Start() {

	for i := 1; i <= wp.Workers; i++ {
		wp.wg.Add(1)
		//time.Sleep(20 * time.Millisecond)
		go wp.Worker(i)
	}
}

func (wp *WorkerPool) Process() {

	if wp.conn != nil {

		for {
			parsedMessage, peer, err := wp.ReadReply()
			if err != nil {
				if isConnectionClosed(err) {
					return
				}
				fmt.Println(err)
			}

			if parsedMessage != nil {

				if parsedMessage.Type == ipv4.ICMPTypeEchoReply {
					body := parsedMessage.Body.(*icmp.Echo)

					wp.mu.Lock()
					job, ok := wp.PendingJobs[body.ID]
					wp.mu.Unlock()

					if ok {
						duration := time.Since(job.SentAt)
						//fmt.Printf("checking type for reply for body ID %v\n", body.ID)
						proto := parsedMessage.Type.Protocol()
						echoReplyLog := fmt.Sprintf("%d bytes from %s: pid =%d, icmp_type=%v, icmp_seq=%d, data=%s, time=%s", body.Len(proto), peer, body.ID, parsedMessage.Type, body.Seq, body.Data, duration)
						wp.logger.Log(echoReplyLog)
						fmt.Printf("%d bytes from %s: pid =%d, icmp_type=%v, icmp_seq=%d, data=%s, time=%s\n", body.Len(proto), peer, body.ID, parsedMessage.Type, body.Seq, body.Data, duration)

						result := &PingResult{
							IP:         peer.String(),
							BodyID:     body.ID,
							Seq:        body.Seq,
							Duration:   duration.String(),
							Attempts:   job.Attempts,
							ReceivedAt: time.Now(),
						}
							job.Result <- result
					}
					continue
				}
				continue
			}
			continue
		}
	}
}

func (wp *WorkerPool) Wait() {
	defer wp.conn.Close()
	close(wp.JobQueue)
	wp.wg.Wait()
	close(wp.Results)
}


func (wp *WorkerPool) cleanup(resultCh chan *PingResult, echoID int) {
	close(resultCh)
	wp.mu.Lock()
	delete(wp.PendingJobs, echoID)
	wp.mu.Unlock()
}

func isConnectionClosed(err error) bool {
	if err != nil && strings.Contains(err.Error(), "use of closed network connection") {
		return true
	}
	return false
}

// GenerateHosts takes a CIDR subnet string (e.g. "192.168.0.0/24")
// and returns a slice of all usable host IPs within that subnet.
//
// The function excludes the network address (first IP) and broadcast address (last IP).
// It supports IPv4 only and returns an error for invalid CIDR input.
func GenerateHosts(subnet string) ([]net.IP, error) {
	ipList := make([]net.IP, 0)
	_, network, err := net.ParseCIDR(subnet)
	if err != nil {
		return nil, fmt.Errorf(ErrParseSubnet.Error(), subnet, err)
	}

	// Convert to 32-bit representation using bitshift (BE)
	maskUint32 := toUint32(network.Mask)
	networkIPUint32 := toUint32(network.IP)

	hosts := (^maskUint32 & 0xFFFFFFFF)

	for i := 1; i < int(hosts); i++ {
		ip := toByte(networkIPUint32 + uint32(i))
		ipList = append(ipList, net.IP(ip))
	}
	//fmt.Println(ipList)
	return ipList, nil
}

func (wp *WorkerPool) SendPing(host net.IP, echoID int, seq int) error {

	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Body: &icmp.Echo{
			ID:   echoID,
			Seq:  seq,
			Data: []byte(""),
		},
	}

	dst, err := net.ResolveIPAddr("ip4", host.String())
	if err != nil {
		errMsg := fmt.Sprintf(ErrResolveIPAddr.Error(), host.String(), err)
		wp.logger.Log(errMsg)
		return fmt.Errorf(ErrResolveIPAddr.Error(), host.String(), err)
	}

	bmessage, err := msg.Marshal(nil)
	if err != nil {
		return fmt.Errorf(ErrMarshalMsg.Error(), err)
	}

	_, err = wp.conn.WriteTo(bmessage, dst)
	if err != nil {
		return fmt.Errorf(ErrWrite.Error(), err)
	}

	return nil
}

func (wp *WorkerPool) ReadReply() (*icmp.Message, net.Addr, error) {
	var peer net.Addr
	err := wp.conn.SetReadDeadline(time.Now().Add(11 * time.Second))
	if err != nil {
		return nil, peer, fmt.Errorf(ErrDeadline.Error(), err)
	}

	breply := make([]byte, 512)
	n, peer, err := wp.conn.ReadFrom(breply)
	if err != nil {
		return nil, peer, fmt.Errorf(ErrRead.Error(), err)
	}

	parsedMessage, err := icmp.ParseMessage(IPv4Protocol, breply[:n])

	if err != nil {
		return nil, peer, fmt.Errorf(ErrParse.Error(), err)
	}

	return parsedMessage, peer, nil
}

func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

// toUint32 converts a 4-byte IP address or subnet mask into a 32-bit unsigned integer.
// Assumes the input slice is in big-endian order and has a length of 4
func toUint32(b []byte) uint32 {
	return (uint32(b[0]) << 24) | (uint32(b[1]) << 16) | (uint32(b[2]) << 8) | (uint32(b[3]))

}

// toByte converts a 32-bit unsigned integer into a 4-byte representation of an IP address.
// The result is returned in big-endian order.
func toByte(ipUint32 uint32) []byte {
	b := make([]byte, 4)
	b[0] = (byte(ipUint32>>24) & 0xFF)
	b[1] = (byte(ipUint32>>16) & 0xFF)
	b[2] = (byte(ipUint32>>8) & 0xFF)
	b[3] = (byte(ipUint32) & 0xFF)
	return b
}

func generateEchoID(ip net.IP, WorkerId int) int {
	return (os.Getpid() & 0xffff) ^ (WorkerId << 8) ^ (int(ipToUint32(ip)))&0xffff
}

