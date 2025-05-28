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

type Result struct {
	IP       string
	BodyID   int
	Duration time.Duration
}

type Job struct {
	ID         int
	Target     net.IP
	Result     chan *Result
	SentAt     time.Time
	Attempts   int
	MaxRetries int
}

type WorkerPool struct {
	workers     int
	jobQueue    chan *Job
	Results     chan *Result
	wg          *sync.WaitGroup
	logger      *logger.Logger
	conn        *icmp.PacketConn
	PendingJobs map[int]*Job
	mu          *sync.Mutex
}

const (
	ListenAddress = "0.0.0.0"
	IPv4Protocol  = 1
)

var (
	ErrResolveIPAddr = errors.New("failed to resolve to target address %v: %w")
	ErrSocketConn    = errors.New("failed to create raw socket to listen for ICMP packets: %w")
	ErrMarshalMsg    = errors.New("failed to marshal icmp message: %w")
	ErrWrite         = errors.New("failed to send ICMP message: %w")
	ErrRead          = errors.New("failed to read ICMP response message: %w")
	ErrDeadline      = errors.New("failed to set read deadline: %w")
	ErrParse         = errors.New("failed to parse ICMP message: %w")
	ErrEchoReply     = errors.New("unexpected ICMP response: got type %v, expected echo reply")
	ErrParseSubnet   = errors.New("failed to parse subnet %v: %w")
	ErrMaskDecode    = errors.New("failed to decode mask %v: %w")
)

func NewWorkerPool(numOfWorkers int, jobQueue int, pingLogger *logger.Logger) *WorkerPool {
	wg := &sync.WaitGroup{}
	conn, err := icmp.ListenPacket("ip4:icmp", ListenAddress)
	if err != nil {
		fmt.Printf(ErrSocketConn.Error(), err)
	}
	return &WorkerPool{
		workers:     numOfWorkers,
		jobQueue:    make(chan *Job, jobQueue),
		Results:     make(chan *Result, jobQueue),
		wg:          wg,
		logger:      pingLogger,
		conn:        conn,
		PendingJobs: make(map[int]*Job),
		mu:          &sync.Mutex{},
	}
}

func (wp *WorkerPool) cleanup(replyCh chan *Result, echoID int) {
	close(replyCh)
	wp.mu.Lock()
	delete(wp.PendingJobs, echoID)
	wp.mu.Unlock()
}

func (wp *WorkerPool) worker(id int) {
	defer wp.wg.Done()
	for job := range wp.jobQueue {
		replyCh := make(chan *Result, 1)
		echoID := generateEchoID(job.Target, id)

		job.ID = echoID
		job.Result = replyCh
		job.SentAt = time.Now()

		wp.mu.Lock()
		wp.PendingJobs[echoID] = job
		wp.mu.Unlock()

		replyReceived := false

		for i := 0; i < job.MaxRetries-1 && !replyReceived; i++ {
			job.Attempts = job.Attempts + 1
			fmt.Printf("Attempt: %d Worker %d pinging IP %v with echoID %v\n", job.Attempts, id, job.Target, echoID)
			err := wp.SendPing(job.Target, echoID, i)
			if err != nil {
				fmt.Println(err)
				wp.cleanup(replyCh, echoID)
			}
		}

		select {
		case reply := <-replyCh:
			wp.Results <- reply
			replyReceived = true
		case <-time.After(2 * time.Second):
		}
		wp.cleanup(replyCh, echoID)

	}

}

func (wp *WorkerPool) Start() {

	for i := 1; i <= wp.workers; i++ {
		wp.wg.Add(1)
		//time.Sleep(20 * time.Millisecond)
		go wp.worker(i)
	}

}

func (wp *WorkerPool) AddJob(job *Job) {
	wp.jobQueue <- job
}

func (wp *WorkerPool) Process() {

	for {
		parsedMessage, peer, err := wp.ReadReply()
		if err != nil {
			if isConnectionClosed(err) {
				return
			}
			fmt.Println(err)
		}

		if parsedMessage.Type == ipv4.ICMPTypeEchoReply {
			body := parsedMessage.Body.(*icmp.Echo)

			wp.mu.Lock()
			job, _ := wp.PendingJobs[body.ID]
			wp.mu.Unlock()

			duration := time.Since(job.SentAt)

			//fmt.Printf("checking type for reply for body ID %v\n", body.ID)

			proto := parsedMessage.Type.Protocol()
			echoReplyLog := fmt.Sprintf("%d bytes from %s: pid =%d, icmp_type=%v, icmp_seq=%d, data=%s, time=%s", body.Len(proto), peer, body.ID, parsedMessage.Type, body.Seq, body.Data, duration)
			wp.logger.Log(echoReplyLog)

			fmt.Printf("%d bytes from %s: pid =%d, icmp_type=%v, icmp_seq=%d, data=%s, time=%s\n", body.Len(proto), peer, body.ID, parsedMessage.Type, body.Seq, body.Data, duration)

			result := &Result{
				IP:       peer.String(),
				BodyID:   body.ID,
				Duration: duration,
			}

			wp.mu.Lock()
			if job, ok := wp.PendingJobs[result.BodyID]; ok {

				if len(job.Result) == 0 {

					job.Result <- result
				}

			}
			wp.mu.Unlock()

		}
	}
}

func (wp *WorkerPool) Wait() {
	defer wp.conn.Close()
	close(wp.jobQueue)
	wp.wg.Wait()
	close(wp.Results)
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

func generateEchoID(ip net.IP, workerId int) int {
	return (os.Getpid() & 0xffff) ^ (workerId << 8) ^ (int(ipToUint32(ip)))&0xffff
}
